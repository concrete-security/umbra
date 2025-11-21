# RA-TLS Toolkit

Portable Remote Attestation for the modern web. This toolkit delivers verified TLS connections to TEEs from browsers (via WASM), Node.js, and Python without relying on platform-native attestation stacks.

---

# 1. Project Overview & Quickstart

## Key Features
- Browser-first verification: full attestation performed inside WASM.
- Transport agnostic: direct TCP for Node/Python, WebSocket/WebTransport tunnel for browsers.
- Configurable policy engine: enforce TCB levels, measurements, advisory IDs.
- Supported TEEs: Intel TDX today; AMD SEV-SNP planned.

## Quickstart Demo

**Prerequisites**
- Rust (stable toolchain)
- `wasm-pack` (`cargo install wasm-pack`)
- Python 3 (serving static assets)
- LLVM/Clang with `wasm32` support

**Run the live demo**
```bash
make demo
```
1. Visit `http://localhost:8080/web-check/`.
2. Confirm the pre-filled target (sample TDX endpoint).
3. Click **Run attestation check**.
4. The browser opens a WebSocket to the proxy, tunnels TLS to the TEE, requests a quote, and verifies it locally.

---

# 2. Architecture & Data Flow

Browsers lack raw TCP sockets and attestation primitives. The toolkit uses a **Tunnel-and-Verify** approach to work around both limitations.

### Data Path

```mermaid
graph LR
    A[Browser (WASM)] -- WebSocket (Encrypted TLS) --> B[Local Proxy]
    B -- Raw TCP (Still Encrypted) --> C[TEE Server]

    subgraph "Browser Context"
        A
        D[Core Verifier]
    end

    subgraph "Untrusted Host"
        B
    end

    subgraph "Trusted Enclave"
        C
    end
```

1. **Tunnel:** Browser connects to the proxy via WebSocket.
2. **Forward:** Proxy opens TCP to the target and blindly forwards bytes; TLS stays end-to-end.
3. **Handshake:** WASM client completes TLS 1.3 over the tunnel.
4. **Quote Fetch:** Client issues an HTTP request inside the tunnel to fetch the hardware quote.
5. **Verification:** `ratls-core` validates the quote against the TLS certificate and user policy.

---

# 3. Component Guide

## `core/`
- `tls_connect`: Handshake + verification over a generic async byte stream.
- `PromiscuousVerifier`: Accepts any X.509 initially, captures leaf cert for post-handshake validation.
- `TdxTcbPolicy`: Encodes acceptable TDX TCB levels and measurements.

## `wasm/`
- `WasmWsStream`: Wraps browser `WebSocket` into `AsyncRead + AsyncWrite` for `rustls`.
- `connect_websocket(target, sni, policy, extra)`: Returns an attested TLS stream plus attestation metadata.
- `run_attestation_check(...)`: Diagnostics helper.

Example:
```javascript
import init, { connect_websocket } from "./pkg/ratls_wasm.js";

await init();

const policy = {
  tee_type: "Tdx",
  allowed_tdx_status: ["UpToDate", "SWHardeningNeeded"]
};

const [stream, attestation] = await connect_websocket(
  "ws://localhost:9000?target=secure-enclave.com:443",
  "secure-enclave.com",
  policy,
  null
);
```

## `proxy/`
- Listens on WebSocket/WebTransport.
- Reads `?target=host:port`.
- Opens TCP and shuttles bytes bi-directionally.
- Must enforce allowlists/ACLs in production to guard against SSRF.

## Additional Directories
- `node/`: NAPI bindings that talk TCP directly with optional tunnel fallback.
- `python/`: PyO3 bindings with async helpers.
- `server-examples/`: Reference RA-TLS servers for TDX/SNP (coming soon).
- `docs/`: Design notes, specs, and task tracking.

---

# 4. Policy Configuration

Policies describe what constitutes an acceptable attestation. The `ratls-core` API (and each binding) consumes a `Policy` struct with the following shape:

```json
{
  "tee_type": "Tdx",
  "allowed_tdx_status": ["UpToDate", "SWHardeningNeeded"],
  "minimum_tcb": {
    "svn": 3,
    "mrseam": "hex bytes",
    "mrtd": "hex bytes"
  },
  "advisories_blocklist": ["INTEL-SA-00999"],
  "allow_debug": false,
  "expected_measurements": [
    {
      "rtmr_index": 3,
      "sha256": "hex bytes for TLS key binding event"
    }
  ]
}
```

| Field | Purpose |
| --- | --- |
| `tee_type` | Chooses the verifier backend (`Tdx`, `Snp`, etc.). |
| `allowed_tdx_status` | Acceptable `TD_REPORT.STATUS` strings (e.g., `UpToDate`). |
| `minimum_tcb` | Lower bounds for SVN plus MRSEAM/MRTD digests to block downgraded builds. |
| `advisories_blocklist` | Rejects quotes referencing these advisory IDs. |
| `allow_debug` | Permits debug TEEs when `true` (default `false`). |
| `expected_measurements` | Optional event/measurement checks, including TLS key hash binding. |

Verification flow with a policy:
1. Confirm the quote matches `tee_type`.
2. Ensure the reported status is in `allowed_tdx_status`.
3. Compare SVN and measurement digests to `minimum_tcb`.
4. Verify no blocked advisories are reported.
5. Enforce `allow_debug`.
6. Recalculate listed measurements (e.g., TLS pubkey hash in RTMR3) and compare to `expected_measurements`.

---

# 5. Protocol Specification

### Step 1: TLS Handshake
- TLS 1.3 with a promiscuous verifier. The certificate is accepted temporarily and recorded.

### Step 2: Quote Retrieval
Client sends an HTTP POST over the established TLS channel:
```http
POST /tdx_quote HTTP/1.1
Host: localhost
Content-Type: application/json
{
  "report_data": "<hex_nonce>"
}
```

Server responds:
```json
{
  "success": true,
  "quote": {
    "quote": "<hex_tdx_quote>",
    "event_log": [...]
  },
  "collateral": { ... }
}
```

### Step 3: Verification
1. Validate the quote signature using Intel PCCS collateral (`dcap-qvl` flow).
2. Ensure `report_data` equals the client nonce (freshness).
3. Recompute RTMR3 by replaying every event log entry in order and ensure the final digest matches the quote.
4. During that replay, locate the TLS key binding event (contains the certificate pubkey hash) to prove the attested workload owns the negotiated TLS key.

---

# Development Reference

## Directory Structure
- `core/`: Verification + policy.
- `wasm/`: Browser bindings.
- `proxy/`: Tunnel service.
- `server-examples/`: Forthcoming reference TEEs.

## Build Commands

| Command | Description |
| --- | --- |
| `make test` | Run Rust unit tests for core and proxy. |
| `make test-wasm` | Check build for the `wasm32` target. |
| `make build-wasm` | Compile the WASM package into `pkg/`. |
| `make proxy` | Run the proxy server standalone. |
| `make web-check` | Serve the static WASM test harness. |
| `make demo` | Build WASM and run proxy + web harness together. |

## Troubleshooting WASM Builds
- Errors like `rust-lld: error: unknown file type` typically mean LLVM/Clang lacks `wasm32` support.
- Run `./setup-wasm-toolchain.sh` on macOS to install a compatible LLVM via Homebrew, then re-run the build.
