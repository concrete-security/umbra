# SNP RA-TLS server demo

Demonstrates generating a TLS key inside an SNP guest, embedding `hash(SPKI)` into the report, building CBOR evidence, and issuing a short-lived RA-TLS certificate with the DICE extension (OID 2.23.133.5.4.9).

## Outline
- Generate TLS keypair; compute SHA-256(SPKI DER).
- Obtain SNP report with SPKI hash in report data; fetch VCEK/endorsements or reference AIA.
- Build CBOR evidence (`fmt: "dice-ratls-v1"`) with SNP TCB claims and optional nonce/timestamp.
- Emit X.509 leaf containing the evidence extension; start rustls/mbedTLS listener.

## TODO
- Add sample cargo project and scripts to mock SNP quote generation for local testing.
