use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use wtransport::Identity;

pub struct TlsMaterial {
    pub identity: Identity,
    pub rustls_config: Arc<rustls::ServerConfig>,
    pub cert_sha256: [u8; 32],
    pub cert_sha256_base64: String,
    pub cert_sha256_hex: String,
}

pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn load_or_generate_tls(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    self_signed: bool,
    extra_sans: &[String],
) -> Result<TlsMaterial> {
    ensure_crypto_provider();

    let (certs, key) = if let (Some(cp), Some(kp)) = (cert_path, key_path) {
        load_pem(cp, kp)?
    } else if self_signed {
        generate_self_signed(extra_sans)?
    } else {
        bail!("Provide --cert and --key, or pass --self-signed for local development");
    };

    let leaf = certs
        .first()
        .context("Certificate chain must contain at least one certificate")?;
    let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
    let cert_sha256_base64 = STANDARD.encode(digest);
    let mut cert_sha256_hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut cert_sha256_hex, "{b:02x}");
    }

    let wt_certs: Vec<wtransport::tls::Certificate> = certs
        .iter()
        .map(|c| wtransport::tls::Certificate::from_der(c.as_ref().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Invalid DER certificate for wtransport: {e}"))?;
    let wt_key = match &key {
        PrivateKeyDer::Pkcs8(k) => {
            wtransport::tls::PrivateKey::from_der_pkcs8(k.secret_pkcs8_der().to_vec())
        }
        _ => bail!("Private key must be in PKCS#8 format"),
    };
    let wt_chain = wtransport::tls::CertificateChain::new(wt_certs);
    let identity = Identity::new(wt_chain, wt_key);

    let rustls_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to build rustls ServerConfig")?,
    );

    Ok(TlsMaterial {
        identity,
        rustls_config,
        cert_sha256: digest,
        cert_sha256_base64,
        cert_sha256_hex,
    })
}

fn load_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("Open cert {}", cert_path.display()))?,
    );
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Parse PEM certificates")?;

    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("Open key {}", key_path.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Parse PEM private key")?
        .context("No private key found in PEM file")?;

    Ok((certs, key))
}

fn generate_self_signed(
    extra_sans: &[String],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    for san in extra_sans {
        if !sans.contains(san) {
            sans.push(san.clone());
        }
    }

    let key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("Generate ECDSA P-256 key pair")?;
    let mut params = CertificateParams::new(sans).context("Create CertificateParams")?;
    params
        .distinguished_name
        .push(DnType::CommonName, "wisp-wt-relay-dev");

    // WebTransport serverCertificateHashes requires validity <= 14 days.
    let now = SystemTime::now();
    params.not_before = (now - Duration::from_secs(3600)).into();
    params.not_after = (now + Duration::from_secs(13 * 24 * 3600)).into();

    let cert = params
        .self_signed(&key_pair)
        .context("Sign self-signed certificate")?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("Serialize PKCS#8 private key: {e}"))?;

    Ok((vec![cert_der], key_der))
}
