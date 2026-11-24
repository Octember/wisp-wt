use crate::security::{SecurityPolicy, ct_eq, resolve_and_check_target};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthProxyRouteConfig {
    pub id: String,
    pub upstream: String,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub inject_headers: HashMap<String, String>,
    #[serde(default)]
    pub strip_request_headers: Vec<String>,
    #[serde(default)]
    pub strip_response_headers: Vec<String>,
    #[serde(default)]
    pub virtual_host: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalConfig {
    pub token: String,
    #[serde(default)]
    pub allowed_routes: Vec<String>,
    #[serde(default)]
    pub allow_raw_tcp: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthProxyFileConfig {
    #[serde(default)]
    pub routes: Vec<AuthProxyRouteConfig>,
    #[serde(default)]
    pub principals: Vec<PrincipalConfig>,
}

#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub id: String,
    pub use_tls: bool,
    pub host: String,
    pub port: u16,
    pub host_header: HeaderValue,
    pub base_path: String,
    pub allowed_methods: Vec<Method>,
    pub allowed_paths: Vec<String>,
    pub inject_headers: Vec<(HeaderName, HeaderValue)>,
    pub strip_request_headers: Vec<HeaderName>,
    pub strip_response_headers: Vec<HeaderName>,
    pub tls_server_name: Option<rustls::pki_types::ServerName<'static>>,
    pub virtual_host: Option<String>,
}

#[derive(Clone)]
pub struct AuthProxy {
    pub routes: HashMap<String, Arc<CompiledRoute>>,
    pub route_order: Vec<String>,
    pub principals: Vec<PrincipalConfig>,
    tls_connector: TlsConnector,
}

#[derive(Debug, Clone)]
pub struct SessionPrincipal {
    pub allowed_routes: Vec<String>,
    pub allow_raw_tcp: bool,
}

#[derive(Serialize)]
struct AdvertisedRoute<'a> {
    id: &'a str,
    #[serde(rename = "virtualHost", skip_serializing_if = "Option::is_none")]
    virtual_host: Option<&'a str>,
}

#[derive(Serialize)]
struct AdvertisedRoutesPayload<'a> {
    routes: Vec<AdvertisedRoute<'a>>,
}

impl AuthProxy {
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Read auth proxy config {}", path.display()))?;
        let cfg: AuthProxyFileConfig = serde_json::from_str(&raw)
            .with_context(|| format!("Parse auth proxy config {}", path.display()))?;

        let mut routes = HashMap::new();
        let mut route_order = Vec::new();
        for r in cfg.routes {
            if r.id.trim().is_empty() {
                bail!("Auth proxy route id must not be empty");
            }
            if routes.contains_key(&r.id) {
                bail!("Duplicate auth proxy route id '{}'", r.id);
            }
            let compiled = compile_route(r)?;
            route_order.push(compiled.id.clone());
            routes.insert(compiled.id.clone(), Arc::new(compiled));
        }

        let mut principals = Vec::with_capacity(cfg.principals.len());
        for (idx, mut p) in cfg.principals.into_iter().enumerate() {
            p.token = expand_env_vars(&p.token)
                .with_context(|| format!("Failed to expand token for principal #{idx}"))?;
            for route_id in &p.allowed_routes {
                if !routes.contains_key(route_id) {
                    bail!(
                        "Principal #{idx} references unknown route id '{route_id}' in allowed_routes"
                    );
                }
            }
            principals.push(p);
        }

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls_connector = TlsConnector::from(Arc::new(tls_cfg));

        info!(
            routes = routes.len(),
            principals = principals.len(),
            "Loaded auth proxy config"
        );

        Ok(Self {
            routes,
            route_order,
            principals,
            tls_connector,
        })
    }

    pub fn resolve_principal(
        &self,
        token: Option<&str>,
        disable_raw_tcp: bool,
    ) -> SessionPrincipal {
        if self.principals.is_empty() {
            return SessionPrincipal {
                allowed_routes: self.route_order.clone(),
                allow_raw_tcp: !disable_raw_tcp,
            };
        }
        if let Some(tok) = token {
            for p in &self.principals {
                if ct_eq(p.token.as_bytes(), tok.as_bytes()) {
                    let allowed_routes = p
                        .allowed_routes
                        .iter()
                        .filter(|id| self.routes.contains_key(*id))
                        .cloned()
                        .collect();
                    return SessionPrincipal {
                        allowed_routes,
                        allow_raw_tcp: p.allow_raw_tcp && !disable_raw_tcp,
                    };
                }
            }
        }
        SessionPrincipal {
            allowed_routes: Vec::new(),
            allow_raw_tcp: false,
        }
    }

    pub fn advertised_extension_json(&self, principal: &SessionPrincipal) -> Vec<u8> {
        let routes: Vec<AdvertisedRoute<'_>> = principal
            .allowed_routes
            .iter()
            .filter_map(|id| self.routes.get(id))
            .map(|r| AdvertisedRoute {
                id: &r.id,
                virtual_host: r.virtual_host.as_deref(),
            })
            .collect();
        serde_json::to_vec(&AdvertisedRoutesPayload { routes }).unwrap_or_else(|_| b"{}".to_vec())
    }

    pub fn get_route(
        &self,
        route_id: &str,
        principal: &SessionPrincipal,
    ) -> Option<Arc<CompiledRoute>> {
        if !principal.allowed_routes.iter().any(|id| id == route_id) {
            return None;
        }
        self.routes.get(route_id).cloned()
    }

    pub fn authorize_route(
        proxy: Option<&Arc<AuthProxy>>,
        principal: Option<&SessionPrincipal>,
        route_id: &str,
    ) -> std::result::Result<(Arc<AuthProxy>, Arc<CompiledRoute>), u8> {
        let (Some(ap), Some(p)) = (proxy, principal) else {
            return Err(crate::protocol::close_reason::BLOCKED);
        };
        let Some(route) = ap.get_route(route_id, p) else {
            return Err(crate::protocol::close_reason::BLOCKED);
        };
        Ok((Arc::clone(ap), route))
    }
}

fn compile_route(r: AuthProxyRouteConfig) -> Result<CompiledRoute> {
    let uri: Uri = r
        .upstream
        .parse()
        .with_context(|| format!("Invalid upstream URI for route {}", r.id))?;
    let scheme = uri
        .scheme_str()
        .map(|s| s.to_ascii_lowercase())
        .context("Upstream URI missing scheme")?;
    let use_tls = match scheme.as_str() {
        "http" => false,
        "https" => true,
        _ => bail!("Unsupported upstream scheme '{scheme}' for route {}", r.id),
    };
    let host = uri.host().context("Upstream URI missing host")?.to_string();
    let default_port = if use_tls { 443 } else { 80 };
    let port = uri.port_u16().unwrap_or(default_port);
    let host_header_str = if uri.port_u16().is_some() {
        format!("{host}:{port}")
    } else {
        host.clone()
    };
    let host_header = HeaderValue::from_str(&host_header_str)
        .with_context(|| format!("Invalid host header '{host_header_str}' for route {}", r.id))?;
    let base_path = uri.path().trim_end_matches('/').to_string();

    let tls_server_name = if use_tls {
        Some(
            rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| anyhow::anyhow!("Invalid upstream TLS server name '{host}'"))?,
        )
    } else {
        None
    };

    let allowed_methods = r
        .allowed_methods
        .into_iter()
        .map(|m| {
            Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                .with_context(|| format!("Invalid allowed method '{m}' for route {}", r.id))
        })
        .collect::<Result<Vec<_>>>()?;

    let strip_request_headers = r
        .strip_request_headers
        .into_iter()
        .map(|h| {
            HeaderName::from_bytes(h.as_bytes())
                .with_context(|| format!("Invalid strip_request_headers '{h}' for route {}", r.id))
        })
        .collect::<Result<Vec<_>>>()?;

    let strip_response_headers = r
        .strip_response_headers
        .into_iter()
        .map(|h| {
            HeaderName::from_bytes(h.as_bytes())
                .with_context(|| format!("Invalid strip_response_headers '{h}' for route {}", r.id))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut inject_headers = Vec::new();
    for (k, v) in r.inject_headers {
        let name = HeaderName::from_bytes(k.as_bytes())
            .with_context(|| format!("Invalid inject header name '{k}'"))?;
        let expanded = expand_env_vars(&v)
            .with_context(|| format!("Route '{}' inject_headers['{k}']", r.id))?;
        let val = HeaderValue::from_str(&expanded)
            .with_context(|| format!("Invalid inject header value for '{k}'"))?;
        inject_headers.push((name, val));
    }

    Ok(CompiledRoute {
        id: r.id,
        use_tls,
        host,
        port,
        host_header,
        base_path,
        allowed_methods,
        allowed_paths: r.allowed_paths,
        inject_headers,
        strip_request_headers,
        strip_response_headers,
        tls_server_name,
        virtual_host: r.virtual_host,
    })
}

fn expand_env_vars(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            bail!("Unclosed env var placeholder in '{input}'");
        };
        let var_name = &after[..end];
        let val = std::env::var(var_name)
            .with_context(|| format!("Missing environment variable '{var_name}'"))?;
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == "/**" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
}

pub async fn handle_http_proxy_io<IO>(
    io: IO,
    route: Arc<CompiledRoute>,
    proxy: Arc<AuthProxy>,
    policy: SecurityPolicy,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let route = Arc::clone(&route);
        let proxy = Arc::clone(&proxy);
        let policy = policy.clone();
        async move { Ok::<_, hyper::Error>(proxy_single_request(req, &route, &proxy, &policy).await) }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(io), service)
        .await
        .context("HTTP auth proxy connection error")
}

fn simple_response(status: StatusCode, msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(msg.as_bytes())))
        .unwrap()
}

async fn proxy_single_request(
    req: Request<Incoming>,
    route: &CompiledRoute,
    proxy: &AuthProxy,
    policy: &SecurityPolicy,
) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let path = parts.uri.path();

    if method == Method::CONNECT || parts.headers.contains_key(hyper::header::UPGRADE) {
        warn!(route_id = %route.id, %method, %path, "auth_proxy_rejected_upgrade_or_connect");
        return simple_response(StatusCode::FORBIDDEN, "CONNECT and Upgrade are not allowed");
    }

    if !route.allowed_methods.is_empty() && !route.allowed_methods.contains(&method) {
        warn!(route_id = %route.id, %method, %path, "auth_proxy_disallowed_method");
        return simple_response(StatusCode::FORBIDDEN, "Method not allowed");
    }

    if !route.allowed_paths.is_empty() && !route.allowed_paths.iter().any(|p| path_matches(p, path))
    {
        warn!(route_id = %route.id, %method, %path, "auth_proxy_disallowed_path");
        return simple_response(StatusCode::FORBIDDEN, "Path not allowed");
    }

    let addrs = match resolve_and_check_target(&route.host, route.port, policy).await {
        Ok(a) => a,
        Err(_) => {
            warn!(route_id = %route.id, %method, %path, "auth_proxy_ssrf_or_dns_blocked");
            return simple_response(StatusCode::FORBIDDEN, "Upstream target blocked");
        }
    };

    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return simple_response(StatusCode::BAD_REQUEST, "Failed to read request body"),
    };

    let upstream_path: std::borrow::Cow<'_, str> = if route.base_path.is_empty() {
        std::borrow::Cow::Borrowed(path_and_query)
    } else {
        std::borrow::Cow::Owned(format!("{}{}", route.base_path, path_and_query))
    };

    let Ok(mut out_req) = Request::builder()
        .method(method.clone())
        .uri(upstream_path.as_ref())
        .body(Full::new(body_bytes))
    else {
        return simple_response(StatusCode::BAD_REQUEST, "Invalid request URI");
    };

    for (name, val) in &parts.headers {
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "proxy-connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
        ) {
            continue;
        }
        if route.strip_request_headers.contains(name) {
            continue;
        }
        out_req.headers_mut().append(name.clone(), val.clone());
    }

    out_req
        .headers_mut()
        .insert(hyper::header::HOST, route.host_header.clone());
    for (name, val) in &route.inject_headers {
        out_req.headers_mut().insert(name.clone(), val.clone());
    }

    let tcp = match tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(&addrs[..])).await {
        Ok(Ok(s)) => s,
        _ => return simple_response(StatusCode::BAD_GATEWAY, "Upstream connect failed"),
    };
    let _ = tcp.set_nodelay(true);

    let resp = if route.use_tls {
        let Some(server_name) = route.tls_server_name.clone() else {
            return simple_response(StatusCode::BAD_GATEWAY, "Invalid upstream TLS server name");
        };
        let tls_stream = match tokio::time::timeout(
            UPSTREAM_TIMEOUT,
            proxy.tls_connector.connect(server_name, tcp),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return simple_response(StatusCode::BAD_GATEWAY, "Upstream TLS handshake failed"),
        };
        tokio::time::timeout(UPSTREAM_TIMEOUT, send_http1_request(tls_stream, out_req)).await
    } else {
        tokio::time::timeout(UPSTREAM_TIMEOUT, send_http1_request(tcp, out_req)).await
    };

    match resp {
        Ok(Ok(mut r)) => {
            let status = r.status();
            let headers = r.headers_mut();
            for h in &route.strip_response_headers {
                headers.remove(h);
            }
            info!(
                route_id = %route.id,
                method = %method,
                path = %path,
                status = status.as_u16(),
                "auth_proxy_request"
            );
            r
        }
        Ok(Err(_)) | Err(_) => {
            warn!(route_id = %route.id, %method, %path, "auth_proxy_upstream_error");
            simple_response(StatusCode::BAD_GATEWAY, "Upstream request failed")
        }
    }
}

async fn send_http1_request<S>(
    stream: S,
    req: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = tokio::time::timeout(UPSTREAM_TIMEOUT, sender.send_request(req)).await??;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok(Response::from_parts(parts, Full::new(bytes)))
}
