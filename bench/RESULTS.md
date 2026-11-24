# Wisp-WS vs. Wisp-WT `tc netem` Benchmark Results

Measured inside Linux (`wisp-wt-netem-bench` Docker container with `--cap-add=NET_ADMIN`), applying `tc netem delay 30ms loss <L>%` (~60 ms RTT) exclusively to client↔relay ports (`4433/udp` for Wisp-WT, `4434/tcp` for Wisp-WS) while leaving relay↔origin (`9000/tcp`) unimpaired.

## Scenario A: Cross-Stream Head-of-Line (HoL) Blocking

2 concurrent 4 MiB bulk downloads + 24 interactive 4 KiB RPCs over the same Wisp session.

| Loss | Wisp-WS Small p50 | Wisp-WT Small p50 | Wisp-WS Small p95 | Wisp-WT Small p95 | Wisp-WS Small p99 / Max | Wisp-WT Small p99 / Max |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **0%** | 170.2 ms | 133.2 ms | 364.8 ms | 172.2 ms | 374.2 ms | **194.2 ms** (1.9x faster) |
| **1%** | 170.0 ms | 158.7 ms | 459.8 ms | 229.4 ms | 643.9 ms | **237.6 ms** (2.7x faster) |
| **2%** | 169.5 ms | 196.9 ms | 415.8 ms | 265.0 ms | 932.6 ms | **341.3 ms** (2.7x faster) |
| **3%** | 172.1 ms | 191.1 ms | 478.2 ms | 325.6 ms | 1119.1 ms | **356.9 ms** (3.1x faster) |

## Key Takeaway

Under 1–3% packet loss, Wisp-over-WebSocket suffers severe cross-stream HoL blocking: a single lost TCP segment stalls all 24 interactive RPCs behind bulk-stream retransmission, pushing p99 latency above **1.1 seconds** at 3% loss. Wisp-over-WebTransport isolates each guest TCP connection onto its own QUIC bidirectional stream, keeping interactive p99 latency at **237–357 ms** (**2.7x–3.1x lower**).
