# TDX RA-TLS server demo

TDX example for generating a TLS key, binding its SPKI hash into a TDX quote, and serving a short-lived RA-TLS certificate that carries tagged CBOR evidence in the DICE extension (OID 2.23.133.5.4.9).

## Outline
- Generate TLS keypair; compute SPKI hash (SHA-256/384).
- Request TDX quote via QGS including the SPKI hash in report data.
- Assemble CBOR evidence with TDX measurements/TCB, workload ID, timestamp, and optional endorsements.
- Emit X.509 leaf with the evidence extension; run rustls/mbedTLS listener.

## TODO
- Create mock quote + collateral fixtures for local validation tests before real hardware integration.
