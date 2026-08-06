# Third-party notices

This document inventories the third-party software distributed with Umbra's release artifacts — the `umbra` CLI binaries and crate, the Console and Security CVM Python packages, the container images, and the Dev CVM image's baked developer tools — together with the license obligations each one carries and how Umbra satisfies them.

The dependency inventory between the `BEGIN GENERATED INVENTORY` and `END GENERATED INVENTORY` markers is produced from the authoritative lockfiles (`Cargo.lock`, `console/uv.lock`, `cvms/security/uv.lock`, the Console and dashboard `package-lock.json` files, and the Codex package lock) by `tools/generate-license-report.py`; regenerate it with that tool rather than editing by hand. Output ordering is deterministic so the regenerated block can be diffed against the checked-in copy.

Every entry in the review queue below is **pending maintainer approval**; the inventory records declared licenses, it does not by itself constitute the owner/legal sign-off tracked by the release gate (ADR 0004).

<!-- BEGIN GENERATED INVENTORY -->

<!-- Regenerate with tools/generate-license-report.py; do not hand-edit between the generated markers. -->

## Inventory summary and review queue

| Inventory | Packages | Permissive | Needs review |
| --- | --- | --- | --- |
| Rust — `umbra` CLI | 282 | 280 | 2 |
| Rust — `umbra-atls-connect` | 267 | 265 | 2 |
| Rust — `atlas-verify-cli` | 271 | 269 | 2 |
| Python — Console | 35 | 34 | 1 |
| Python — Security CVM | 54 | 48 | 6 |
| npm — Console runtime (`phala` CLI) | 158 | 158 | 0 |
| npm — dashboard build graph (build-time only) | 55 | 55 | 0 |
| npm — Codex (Dev CVM image) | 7 | 7 | 0 |

Every row below is unapproved until a maintainer records a decision in this file's **Maintainer review queue** section.

| Inventory | Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- | --- |
| Rust — `umbra` CLI | `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| Rust — `umbra` CLI | `webpki-roots` | 1.0.7 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| Rust — `umbra-atls-connect` | `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| Rust — `umbra-atls-connect` | `webpki-roots` | 1.0.7 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| Rust — `atlas-verify-cli` | `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| Rust — `atlas-verify-cli` | `webpki-roots` | 1.0.8 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| Python — Console | `certifi` | 2026.4.22 | MPL-2.0 | weak copyleft | from trove classifiers |
| Python — Security CVM | `certifi` | 2026.4.22 | MPL-2.0 | weak copyleft | from trove classifiers |
| Python — Security CVM | `ldap3` | 2.9.1 | LGPL-3.0-only | weak copyleft | from trove classifiers |
| Python — Security CVM | `mitmproxy-windows` | 0.11.5 | LGPL-3.0-or-later | weak copyleft | installed only when: os_name == 'nt' |
| Python — Security CVM | `publicsuffix2` | 2.20191221 | MIT AND MPL-2.0 | weak copyleft | from trove classifiers |
| Python — Security CVM | `pydivert` | 2.1.0 | LGPL-3.0-or-later | weak copyleft | from trove classifiers — installed only when: sys_platform == 'win32' |
| Python — Security CVM | `urwid` | 2.6.16 | LGPL-2.1-only | weak copyleft | from the prose `License` field |

## Rust — `umbra` CLI

Locked non-dev closure of `umbra-cli`, unioned across the published targets (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`). Distributed as release binaries and as the `umbra-cli` crate.

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `aho-corasick` | 1.1.4 | Unlicense OR MIT | permissive | — |
| `anstream` | 1.0.0 | MIT OR Apache-2.0 | permissive | — |
| `anstyle` | 1.0.14 | MIT OR Apache-2.0 | permissive | — |
| `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 | permissive | — |
| `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 | permissive | — |
| `anyhow` | 1.0.102 | MIT OR Apache-2.0 | permissive | — |
| `arrayvec` | 0.7.6 | MIT OR Apache-2.0 | permissive | — |
| `asn1_der` | 0.7.7 | BSD-2-Clause OR MIT | permissive | — |
| `async-trait` | 0.1.89 | MIT OR Apache-2.0 | permissive | — |
| `atlas-rs` | 0.2.0 | MIT | permissive | — |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT | permissive | — |
| `autocfg` | 1.5.0 | Apache-2.0 OR MIT | permissive | — |
| `aws-lc-rs` | 1.17.0 | ISC AND (Apache-2.0 OR ISC) | permissive | — |
| `aws-lc-sys` | 0.41.0 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) | permissive | — |
| `base16ct` | 0.2.0 | Apache-2.0 OR MIT | permissive | — |
| `base64` | 0.13.1 | MIT/Apache-2.0 | permissive | — |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | permissive | — |
| `base64ct` | 1.8.3 | Apache-2.0 OR MIT | permissive | — |
| `bitflags` | 2.11.1 | MIT OR Apache-2.0 | permissive | — |
| `bitvec` | 1.0.1 | MIT | permissive | — |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 | permissive | — |
| `bon` | 3.9.1 | MIT OR Apache-2.0 | permissive | — |
| `bon-macros` | 3.9.1 | MIT OR Apache-2.0 | permissive | — |
| `borsh` | 1.6.1 | MIT OR Apache-2.0 | permissive | — |
| `borsh-derive` | 1.6.1 | Apache-2.0 | permissive | — |
| `bumpalo` | 3.20.2 | MIT OR Apache-2.0 | permissive | — |
| `byte-slice-cast` | 1.2.3 | MIT | permissive | — |
| `byteorder` | 1.5.0 | Unlicense OR MIT | permissive | — |
| `bytes` | 1.11.1 | MIT | permissive | — |
| `cc` | 1.2.61 | MIT OR Apache-2.0 | permissive | — |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | permissive | — |
| `cfg_aliases` | 0.2.1 | MIT | permissive | — |
| `chrono` | 0.4.44 | MIT OR Apache-2.0 | permissive | — |
| `clap` | 4.6.1 | MIT OR Apache-2.0 | permissive | — |
| `clap_builder` | 4.6.0 | MIT OR Apache-2.0 | permissive | — |
| `clap_complete` | 4.6.5 | MIT OR Apache-2.0 | permissive | — |
| `clap_derive` | 4.6.1 | MIT OR Apache-2.0 | permissive | — |
| `clap_lex` | 1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `cmake` | 0.1.58 | MIT OR Apache-2.0 | permissive | — |
| `colorchoice` | 1.0.5 | MIT OR Apache-2.0 | permissive | — |
| `const-oid` | 0.9.6 | Apache-2.0 OR MIT | permissive | — |
| `const_format` | 0.2.36 | Zlib | permissive | — |
| `const_format_proc_macros` | 0.2.34 | Zlib | permissive | — |
| `convert_case` | 0.10.0 | MIT | permissive | — |
| `core-foundation` | 0.10.1 | MIT OR Apache-2.0 | permissive | — |
| `core-foundation-sys` | 0.8.7 | MIT OR Apache-2.0 | permissive | — |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 | permissive | — |
| `critical-section` | 1.2.0 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-channel` | 0.5.15 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-epoch` | 0.9.18 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-utils` | 0.8.21 | MIT OR Apache-2.0 | permissive | — |
| `crypto-bigint` | 0.5.5 | Apache-2.0 OR MIT | permissive | — |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 | permissive | — |
| `curve25519-dalek` | 4.1.3 | BSD-3-Clause | permissive | — |
| `curve25519-dalek-derive` | 0.1.1 | MIT/Apache-2.0 | permissive | — |
| `darling` | 0.23.0 | MIT | permissive | — |
| `darling_core` | 0.23.0 | MIT | permissive | — |
| `darling_macro` | 0.23.0 | MIT | permissive | — |
| `data-encoding` | 2.11.0 | MIT | permissive | — |
| `dcap-qvl` | 0.3.12 | MIT | permissive | — |
| `dcap-qvl-webpki` | 0.103.4+dcap.1 | ISC | permissive | — |
| `der` | 0.7.10 | Apache-2.0 OR MIT | permissive | — |
| `der_derive` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `derive_more` | 1.0.0 | MIT | permissive | — |
| `derive_more` | 2.1.1 | MIT | permissive | — |
| `derive_more-impl` | 1.0.0 | MIT | permissive | — |
| `derive_more-impl` | 2.1.1 | MIT | permissive | — |
| `digest` | 0.10.7 | MIT OR Apache-2.0 | permissive | — |
| `displaydoc` | 0.2.5 | MIT OR Apache-2.0 | permissive | — |
| `dstack-sdk-types` | 0.1.2 | MIT | permissive | — |
| `dunce` | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 | permissive | — |
| `ecdsa` | 0.16.9 | Apache-2.0 OR MIT | permissive | — |
| `ed25519` | 2.2.3 | Apache-2.0 OR MIT | permissive | — |
| `ed25519-dalek` | 2.2.0 | BSD-3-Clause | permissive | — |
| `elliptic-curve` | 0.13.8 | Apache-2.0 OR MIT | permissive | — |
| `enum-as-inner` | 0.6.1 | MIT/Apache-2.0 | permissive | — |
| `env_filter` | 1.0.1 | MIT OR Apache-2.0 | permissive | — |
| `env_logger` | 0.11.10 | MIT OR Apache-2.0 | permissive | — |
| `equivalent` | 1.0.2 | Apache-2.0 OR MIT | permissive | — |
| `ff` | 0.13.1 | MIT/Apache-2.0 | permissive | — |
| `find-msvc-tools` | 0.1.9 | MIT OR Apache-2.0 | permissive | — |
| `flagset` | 0.4.7 | Apache-2.0 | permissive | — |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | permissive | — |
| `fs_extra` | 1.3.0 | MIT | permissive | — |
| `funty` | 2.0.0 | MIT | permissive | — |
| `futures` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-channel` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-core` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-executor` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-io` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-macro` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-sink` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-task` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-util` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `generic-array` | 0.14.7 | MIT | permissive | — |
| `getrandom` | 0.2.17 | MIT OR Apache-2.0 | permissive | — |
| `getrandom` | 0.3.4 | MIT OR Apache-2.0 | permissive | — |
| `getrandom` | 0.4.2 | MIT OR Apache-2.0 | permissive | — |
| `group` | 0.13.0 | MIT/Apache-2.0 | permissive | — |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | permissive | — |
| `heck` | 0.5.0 | MIT OR Apache-2.0 | permissive | — |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | permissive | — |
| `hickory-proto` | 0.25.2 | MIT OR Apache-2.0 | permissive | — |
| `hickory-resolver` | 0.25.2 | MIT OR Apache-2.0 | permissive | — |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 | permissive | — |
| `home` | 0.5.12 | MIT OR Apache-2.0 | permissive | — |
| `http` | 1.4.0 | MIT OR Apache-2.0 | permissive | — |
| `http-body` | 1.0.1 | MIT | permissive | — |
| `http-body-util` | 0.1.3 | MIT | permissive | — |
| `httparse` | 1.10.1 | MIT OR Apache-2.0 | permissive | — |
| `hyper` | 1.9.0 | MIT | permissive | — |
| `hyper-rustls` | 0.27.9 | Apache-2.0 OR ISC OR MIT | permissive | — |
| `hyper-util` | 0.1.20 | MIT | permissive | — |
| `iana-time-zone` | 0.1.65 | MIT OR Apache-2.0 | permissive | — |
| `icu_collections` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_locale_core` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_normalizer` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_normalizer_data` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_properties` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_properties_data` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_provider` | 2.2.0 | Unicode-3.0 | permissive | — |
| `ident_case` | 1.0.1 | MIT/Apache-2.0 | permissive | — |
| `idna` | 1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT | permissive | — |
| `impl-trait-for-tuples` | 0.2.3 | Apache-2.0/MIT | permissive | — |
| `indexmap` | 2.14.0 | Apache-2.0 OR MIT | permissive | — |
| `ipnet` | 2.12.0 | MIT OR Apache-2.0 | permissive | — |
| `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 | permissive | — |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 | permissive | — |
| `jiff` | 0.2.24 | Unlicense OR MIT | permissive | — |
| `jobserver` | 0.1.34 | MIT OR Apache-2.0 | permissive | — |
| `js-sys` | 0.3.95 | MIT OR Apache-2.0 | permissive | — |
| `konst` | 0.2.20 | Zlib | permissive | — |
| `konst_macro_rules` | 0.2.19 | Zlib | permissive | — |
| `lazy_static` | 1.5.0 | MIT OR Apache-2.0 | permissive | — |
| `libc` | 0.2.186 | MIT OR Apache-2.0 | permissive | — |
| `libm` | 0.2.16 | MIT | permissive | — |
| `litemap` | 0.8.2 | Unicode-3.0 | permissive | — |
| `lock_api` | 0.4.14 | MIT OR Apache-2.0 | permissive | — |
| `log` | 0.4.29 | MIT OR Apache-2.0 | permissive | — |
| `lru-slab` | 0.1.2 | MIT OR Apache-2.0 OR Zlib | permissive | — |
| `memchr` | 2.8.0 | Unlicense OR MIT | permissive | — |
| `mio` | 1.2.0 | MIT | permissive | — |
| `moka` | 0.12.15 | (MIT OR Apache-2.0) AND Apache-2.0 | permissive | — |
| `num-bigint-dig` | 0.8.6 | MIT/Apache-2.0 | permissive | — |
| `num-integer` | 0.1.46 | MIT OR Apache-2.0 | permissive | — |
| `num-iter` | 0.1.45 | MIT OR Apache-2.0 | permissive | — |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 | permissive | — |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 | permissive | — |
| `p256` | 0.13.2 | Apache-2.0 OR MIT | permissive | — |
| `p384` | 0.13.1 | Apache-2.0 OR MIT | permissive | — |
| `parity-scale-codec` | 3.7.5 | Apache-2.0 | permissive | — |
| `parity-scale-codec-derive` | 3.7.5 | Apache-2.0 | permissive | — |
| `parking_lot` | 0.12.5 | MIT OR Apache-2.0 | permissive | — |
| `parking_lot_core` | 0.9.12 | MIT OR Apache-2.0 | permissive | — |
| `pem` | 3.0.6 | MIT | permissive | — |
| `pem-rfc7468` | 0.7.0 | Apache-2.0 OR MIT | permissive | — |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 | permissive | — |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT | permissive | — |
| `pkcs1` | 0.7.5 | Apache-2.0 OR MIT | permissive | — |
| `pkcs8` | 0.10.2 | Apache-2.0 OR MIT | permissive | — |
| `portable-atomic` | 1.13.1 | Apache-2.0 OR MIT | permissive | — |
| `potential_utf` | 0.1.5 | Unicode-3.0 | permissive | — |
| `ppv-lite86` | 0.2.21 | MIT OR Apache-2.0 | permissive | — |
| `prettyplease` | 0.2.37 | MIT OR Apache-2.0 | permissive | — |
| `primeorder` | 0.13.6 | Apache-2.0 OR MIT | permissive | — |
| `proc-macro-crate` | 3.5.0 | MIT OR Apache-2.0 | permissive | — |
| `proc-macro2` | 1.0.106 | MIT OR Apache-2.0 | permissive | — |
| `quinn` | 0.11.9 | MIT OR Apache-2.0 | permissive | — |
| `quinn-proto` | 0.11.14 | MIT OR Apache-2.0 | permissive | — |
| `quinn-udp` | 0.5.14 | MIT OR Apache-2.0 | permissive | — |
| `quote` | 1.0.45 | MIT OR Apache-2.0 | permissive | — |
| `radium` | 0.7.0 | MIT | permissive | — |
| `rand` | 0.8.6 | MIT OR Apache-2.0 | permissive | — |
| `rand` | 0.9.4 | MIT OR Apache-2.0 | permissive | — |
| `rand_chacha` | 0.3.1 | MIT OR Apache-2.0 | permissive | — |
| `rand_chacha` | 0.9.0 | MIT OR Apache-2.0 | permissive | — |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 | permissive | — |
| `rand_core` | 0.9.5 | MIT OR Apache-2.0 | permissive | — |
| `regex` | 1.12.3 | MIT OR Apache-2.0 | permissive | — |
| `regex-automata` | 0.4.14 | MIT OR Apache-2.0 | permissive | — |
| `regex-syntax` | 0.8.10 | MIT OR Apache-2.0 | permissive | — |
| `reqwest` | 0.12.28 | MIT OR Apache-2.0 | permissive | — |
| `resolv-conf` | 0.7.6 | MIT OR Apache-2.0 | permissive | — |
| `rfc6979` | 0.4.0 | Apache-2.0 OR MIT | permissive | — |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | permissive | — |
| `rsa` | 0.9.10 | MIT OR Apache-2.0 | permissive | — |
| `rustc-hash` | 2.1.2 | Apache-2.0 OR MIT | permissive | — |
| `rustc_version` | 0.4.1 | MIT OR Apache-2.0 | permissive | — |
| `rustls` | 0.23.40 | Apache-2.0 OR ISC OR MIT | permissive | — |
| `rustls-pki-types` | 1.14.1 | MIT OR Apache-2.0 | permissive | — |
| `rustls-webpki` | 0.103.13 | ISC | permissive | — |
| `rustversion` | 1.0.22 | MIT OR Apache-2.0 | permissive | — |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 | permissive | — |
| `scale-info` | 2.11.6 | Apache-2.0 | permissive | — |
| `scale-info-derive` | 2.11.6 | Apache-2.0 | permissive | — |
| `scopeguard` | 1.2.0 | MIT OR Apache-2.0 | permissive | — |
| `sec1` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `semver` | 1.0.28 | MIT OR Apache-2.0 | permissive | — |
| `serde` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde-human-bytes` | 0.1.2 | MIT OR Apache-2.0 | permissive | — |
| `serde-wasm-bindgen` | 0.6.5 | MIT | permissive | — |
| `serde_core` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde_derive` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde_json` | 1.0.149 | MIT OR Apache-2.0 | permissive | — |
| `serde_spanned` | 1.1.1 | MIT OR Apache-2.0 | permissive | — |
| `serde_urlencoded` | 0.7.1 | MIT/Apache-2.0 | permissive | — |
| `sha1` | 0.10.6 | MIT OR Apache-2.0 | permissive | — |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | permissive | — |
| `shlex` | 1.3.0 | MIT OR Apache-2.0 | permissive | — |
| `signature` | 2.2.0 | Apache-2.0 OR MIT | permissive | — |
| `slab` | 0.4.12 | MIT | permissive | — |
| `smallvec` | 1.15.1 | MIT OR Apache-2.0 | permissive | — |
| `socket2` | 0.6.3 | MIT OR Apache-2.0 | permissive | — |
| `spin` | 0.9.9 | MIT | permissive | — |
| `spki` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | permissive | — |
| `strsim` | 0.11.1 | MIT | permissive | — |
| `subtle` | 2.6.1 | BSD-3-Clause | permissive | — |
| `syn` | 2.0.117 | MIT OR Apache-2.0 | permissive | — |
| `sync_wrapper` | 1.0.2 | Apache-2.0 | permissive | — |
| `synstructure` | 0.13.2 | MIT | permissive | — |
| `tagptr` | 0.2.0 | MIT/Apache-2.0 | permissive | — |
| `tap` | 1.0.1 | MIT | permissive | — |
| `thiserror` | 2.0.18 | MIT OR Apache-2.0 | permissive | — |
| `thiserror-impl` | 2.0.18 | MIT OR Apache-2.0 | permissive | — |
| `tinystr` | 0.8.3 | Unicode-3.0 | permissive | — |
| `tinyvec` | 1.11.0 | Zlib OR Apache-2.0 OR MIT | permissive | — |
| `tinyvec_macros` | 0.1.1 | MIT OR Apache-2.0 OR Zlib | permissive | — |
| `tokio` | 1.52.3 | MIT | permissive | — |
| `tokio-macros` | 2.7.0 | MIT | permissive | — |
| `tokio-rustls` | 0.26.4 | MIT OR Apache-2.0 | permissive | — |
| `toml` | 0.9.12+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_datetime` | 0.7.5+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_datetime` | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_edit` | 0.25.11+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_parser` | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_writer` | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `tower` | 0.5.3 | MIT | permissive | — |
| `tower-http` | 0.6.10 | MIT | permissive | — |
| `tower-layer` | 0.3.3 | MIT | permissive | — |
| `tower-service` | 0.3.3 | MIT | permissive | — |
| `tracing` | 0.1.44 | MIT | permissive | — |
| `tracing-attributes` | 0.1.31 | MIT | permissive | — |
| `tracing-core` | 0.1.36 | MIT | permissive | — |
| `try-lock` | 0.2.5 | MIT | permissive | — |
| `typenum` | 1.20.0 | MIT OR Apache-2.0 | permissive | — |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | permissive | — |
| `unicode-segmentation` | 1.13.2 | MIT OR Apache-2.0 | permissive | — |
| `unicode-xid` | 0.2.6 | MIT OR Apache-2.0 | permissive | — |
| `untrusted` | 0.9.0 | ISC | permissive | — |
| `url` | 2.5.8 | MIT OR Apache-2.0 | permissive | — |
| `urlencoding` | 2.1.3 | MIT | permissive | — |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT | permissive | — |
| `utf8parse` | 0.2.2 | Apache-2.0 OR MIT | permissive | — |
| `uuid` | 1.23.1 | Apache-2.0 OR MIT | permissive | — |
| `version_check` | 0.9.5 | MIT/Apache-2.0 | permissive | — |
| `want` | 0.3.1 | MIT | permissive | — |
| `wasm-bindgen` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-futures` | 0.4.68 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-macro` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-macro-support` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-shared` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `webbrowser` | 1.2.1 | MIT OR Apache-2.0 | permissive | — |
| `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| `webpki-roots` | 1.0.7 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| `winnow` | 0.7.15 | MIT | permissive | — |
| `winnow` | 1.0.3 | MIT | permissive | — |
| `writeable` | 0.6.3 | Unicode-3.0 | permissive | — |
| `wyz` | 0.5.1 | MIT | permissive | — |
| `x509-cert` | 0.2.5 | Apache-2.0 OR MIT | permissive | — |
| `yoke` | 0.8.2 | Unicode-3.0 | permissive | — |
| `yoke-derive` | 0.8.2 | Unicode-3.0 | permissive | — |
| `zerocopy` | 0.8.48 | BSD-2-Clause OR Apache-2.0 OR MIT | permissive | — |
| `zerofrom` | 0.1.8 | Unicode-3.0 | permissive | — |
| `zerofrom-derive` | 0.1.7 | Unicode-3.0 | permissive | — |
| `zeroize` | 1.8.2 | Apache-2.0 OR MIT | permissive | — |
| `zeroize_derive` | 1.4.3 | Apache-2.0 OR MIT | permissive | — |
| `zerotrie` | 0.2.4 | Unicode-3.0 | permissive | — |
| `zerovec` | 0.11.6 | Unicode-3.0 | permissive | — |
| `zerovec-derive` | 0.11.3 | Unicode-3.0 | permissive | — |
| `zmij` | 1.0.21 | MIT | permissive | — |

## Rust — `umbra-atls-connect`

Locked non-dev closure for `x86_64-unknown-linux-gnu`. Distributed inside the Dev CVM image.

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `aho-corasick` | 1.1.4 | Unlicense OR MIT | permissive | — |
| `anstream` | 1.0.0 | MIT OR Apache-2.0 | permissive | — |
| `anstyle` | 1.0.14 | MIT OR Apache-2.0 | permissive | — |
| `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 | permissive | — |
| `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 | permissive | — |
| `anyhow` | 1.0.102 | MIT OR Apache-2.0 | permissive | — |
| `arrayvec` | 0.7.6 | MIT OR Apache-2.0 | permissive | — |
| `asn1_der` | 0.7.7 | BSD-2-Clause OR MIT | permissive | — |
| `async-trait` | 0.1.89 | MIT OR Apache-2.0 | permissive | — |
| `atlas-rs` | 0.2.0 | MIT | permissive | — |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT | permissive | — |
| `autocfg` | 1.5.0 | Apache-2.0 OR MIT | permissive | — |
| `aws-lc-rs` | 1.17.0 | ISC AND (Apache-2.0 OR ISC) | permissive | — |
| `aws-lc-sys` | 0.41.0 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) | permissive | — |
| `base16ct` | 0.2.0 | Apache-2.0 OR MIT | permissive | — |
| `base64` | 0.13.1 | MIT/Apache-2.0 | permissive | — |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | permissive | — |
| `base64ct` | 1.8.3 | Apache-2.0 OR MIT | permissive | — |
| `bitflags` | 2.11.1 | MIT OR Apache-2.0 | permissive | — |
| `bitvec` | 1.0.1 | MIT | permissive | — |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 | permissive | — |
| `bon` | 3.9.1 | MIT OR Apache-2.0 | permissive | — |
| `bon-macros` | 3.9.1 | MIT OR Apache-2.0 | permissive | — |
| `borsh` | 1.6.1 | MIT OR Apache-2.0 | permissive | — |
| `borsh-derive` | 1.6.1 | Apache-2.0 | permissive | — |
| `bumpalo` | 3.20.2 | MIT OR Apache-2.0 | permissive | — |
| `byte-slice-cast` | 1.2.3 | MIT | permissive | — |
| `byteorder` | 1.5.0 | Unlicense OR MIT | permissive | — |
| `bytes` | 1.11.1 | MIT | permissive | — |
| `cc` | 1.2.61 | MIT OR Apache-2.0 | permissive | — |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | permissive | — |
| `cfg_aliases` | 0.2.1 | MIT | permissive | — |
| `chrono` | 0.4.44 | MIT OR Apache-2.0 | permissive | — |
| `cmake` | 0.1.58 | MIT OR Apache-2.0 | permissive | — |
| `colorchoice` | 1.0.5 | MIT OR Apache-2.0 | permissive | — |
| `const-oid` | 0.9.6 | Apache-2.0 OR MIT | permissive | — |
| `const_format` | 0.2.36 | Zlib | permissive | — |
| `const_format_proc_macros` | 0.2.34 | Zlib | permissive | — |
| `convert_case` | 0.10.0 | MIT | permissive | — |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 | permissive | — |
| `critical-section` | 1.2.0 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-channel` | 0.5.15 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-epoch` | 0.9.18 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-utils` | 0.8.21 | MIT OR Apache-2.0 | permissive | — |
| `crypto-bigint` | 0.5.5 | Apache-2.0 OR MIT | permissive | — |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 | permissive | — |
| `curve25519-dalek` | 4.1.3 | BSD-3-Clause | permissive | — |
| `curve25519-dalek-derive` | 0.1.1 | MIT/Apache-2.0 | permissive | — |
| `darling` | 0.23.0 | MIT | permissive | — |
| `darling_core` | 0.23.0 | MIT | permissive | — |
| `darling_macro` | 0.23.0 | MIT | permissive | — |
| `data-encoding` | 2.11.0 | MIT | permissive | — |
| `dcap-qvl` | 0.3.12 | MIT | permissive | — |
| `dcap-qvl-webpki` | 0.103.4+dcap.1 | ISC | permissive | — |
| `der` | 0.7.10 | Apache-2.0 OR MIT | permissive | — |
| `der_derive` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `derive_more` | 1.0.0 | MIT | permissive | — |
| `derive_more` | 2.1.1 | MIT | permissive | — |
| `derive_more-impl` | 1.0.0 | MIT | permissive | — |
| `derive_more-impl` | 2.1.1 | MIT | permissive | — |
| `digest` | 0.10.7 | MIT OR Apache-2.0 | permissive | — |
| `displaydoc` | 0.2.5 | MIT OR Apache-2.0 | permissive | — |
| `dstack-sdk-types` | 0.1.2 | MIT | permissive | — |
| `dunce` | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 | permissive | — |
| `ecdsa` | 0.16.9 | Apache-2.0 OR MIT | permissive | — |
| `ed25519` | 2.2.3 | Apache-2.0 OR MIT | permissive | — |
| `ed25519-dalek` | 2.2.0 | BSD-3-Clause | permissive | — |
| `elliptic-curve` | 0.13.8 | Apache-2.0 OR MIT | permissive | — |
| `enum-as-inner` | 0.6.1 | MIT/Apache-2.0 | permissive | — |
| `env_filter` | 1.0.1 | MIT OR Apache-2.0 | permissive | — |
| `env_logger` | 0.11.10 | MIT OR Apache-2.0 | permissive | — |
| `equivalent` | 1.0.2 | Apache-2.0 OR MIT | permissive | — |
| `ff` | 0.13.1 | MIT/Apache-2.0 | permissive | — |
| `find-msvc-tools` | 0.1.9 | MIT OR Apache-2.0 | permissive | — |
| `flagset` | 0.4.7 | Apache-2.0 | permissive | — |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | permissive | — |
| `fs_extra` | 1.3.0 | MIT | permissive | — |
| `funty` | 2.0.0 | MIT | permissive | — |
| `futures` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-channel` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-core` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-executor` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-io` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-macro` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-sink` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-task` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-util` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `generic-array` | 0.14.7 | MIT | permissive | — |
| `getrandom` | 0.2.17 | MIT OR Apache-2.0 | permissive | — |
| `getrandom` | 0.3.4 | MIT OR Apache-2.0 | permissive | — |
| `getrandom` | 0.4.2 | MIT OR Apache-2.0 | permissive | — |
| `group` | 0.13.0 | MIT/Apache-2.0 | permissive | — |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | permissive | — |
| `heck` | 0.5.0 | MIT OR Apache-2.0 | permissive | — |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | permissive | — |
| `hickory-proto` | 0.25.2 | MIT OR Apache-2.0 | permissive | — |
| `hickory-resolver` | 0.25.2 | MIT OR Apache-2.0 | permissive | — |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 | permissive | — |
| `http` | 1.4.0 | MIT OR Apache-2.0 | permissive | — |
| `http-body` | 1.0.1 | MIT | permissive | — |
| `http-body-util` | 0.1.3 | MIT | permissive | — |
| `httparse` | 1.10.1 | MIT OR Apache-2.0 | permissive | — |
| `hyper` | 1.9.0 | MIT | permissive | — |
| `hyper-rustls` | 0.27.9 | Apache-2.0 OR ISC OR MIT | permissive | — |
| `hyper-util` | 0.1.20 | MIT | permissive | — |
| `iana-time-zone` | 0.1.65 | MIT OR Apache-2.0 | permissive | — |
| `icu_collections` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_locale_core` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_normalizer` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_normalizer_data` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_properties` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_properties_data` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_provider` | 2.2.0 | Unicode-3.0 | permissive | — |
| `ident_case` | 1.0.1 | MIT/Apache-2.0 | permissive | — |
| `idna` | 1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT | permissive | — |
| `impl-trait-for-tuples` | 0.2.3 | Apache-2.0/MIT | permissive | — |
| `indexmap` | 2.14.0 | Apache-2.0 OR MIT | permissive | — |
| `ipnet` | 2.12.0 | MIT OR Apache-2.0 | permissive | — |
| `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 | permissive | — |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 | permissive | — |
| `jiff` | 0.2.24 | Unlicense OR MIT | permissive | — |
| `jobserver` | 0.1.34 | MIT OR Apache-2.0 | permissive | — |
| `js-sys` | 0.3.95 | MIT OR Apache-2.0 | permissive | — |
| `konst` | 0.2.20 | Zlib | permissive | — |
| `konst_macro_rules` | 0.2.19 | Zlib | permissive | — |
| `lazy_static` | 1.5.0 | MIT OR Apache-2.0 | permissive | — |
| `libc` | 0.2.186 | MIT OR Apache-2.0 | permissive | — |
| `libm` | 0.2.16 | MIT | permissive | — |
| `litemap` | 0.8.2 | Unicode-3.0 | permissive | — |
| `lock_api` | 0.4.14 | MIT OR Apache-2.0 | permissive | — |
| `log` | 0.4.29 | MIT OR Apache-2.0 | permissive | — |
| `lru-slab` | 0.1.2 | MIT OR Apache-2.0 OR Zlib | permissive | — |
| `memchr` | 2.8.0 | Unlicense OR MIT | permissive | — |
| `mio` | 1.2.0 | MIT | permissive | — |
| `moka` | 0.12.15 | (MIT OR Apache-2.0) AND Apache-2.0 | permissive | — |
| `num-bigint-dig` | 0.8.6 | MIT/Apache-2.0 | permissive | — |
| `num-integer` | 0.1.46 | MIT OR Apache-2.0 | permissive | — |
| `num-iter` | 0.1.45 | MIT OR Apache-2.0 | permissive | — |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 | permissive | — |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 | permissive | — |
| `p256` | 0.13.2 | Apache-2.0 OR MIT | permissive | — |
| `p384` | 0.13.1 | Apache-2.0 OR MIT | permissive | — |
| `parity-scale-codec` | 3.7.5 | Apache-2.0 | permissive | — |
| `parity-scale-codec-derive` | 3.7.5 | Apache-2.0 | permissive | — |
| `parking_lot` | 0.12.5 | MIT OR Apache-2.0 | permissive | — |
| `parking_lot_core` | 0.9.12 | MIT OR Apache-2.0 | permissive | — |
| `pem` | 3.0.6 | MIT | permissive | — |
| `pem-rfc7468` | 0.7.0 | Apache-2.0 OR MIT | permissive | — |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 | permissive | — |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT | permissive | — |
| `pkcs1` | 0.7.5 | Apache-2.0 OR MIT | permissive | — |
| `pkcs8` | 0.10.2 | Apache-2.0 OR MIT | permissive | — |
| `portable-atomic` | 1.13.1 | Apache-2.0 OR MIT | permissive | — |
| `potential_utf` | 0.1.5 | Unicode-3.0 | permissive | — |
| `ppv-lite86` | 0.2.21 | MIT OR Apache-2.0 | permissive | — |
| `prettyplease` | 0.2.37 | MIT OR Apache-2.0 | permissive | — |
| `primeorder` | 0.13.6 | Apache-2.0 OR MIT | permissive | — |
| `proc-macro-crate` | 3.5.0 | MIT OR Apache-2.0 | permissive | — |
| `proc-macro2` | 1.0.106 | MIT OR Apache-2.0 | permissive | — |
| `quinn` | 0.11.9 | MIT OR Apache-2.0 | permissive | — |
| `quinn-proto` | 0.11.14 | MIT OR Apache-2.0 | permissive | — |
| `quinn-udp` | 0.5.14 | MIT OR Apache-2.0 | permissive | — |
| `quote` | 1.0.45 | MIT OR Apache-2.0 | permissive | — |
| `radium` | 0.7.0 | MIT | permissive | — |
| `rand` | 0.8.6 | MIT OR Apache-2.0 | permissive | — |
| `rand` | 0.9.4 | MIT OR Apache-2.0 | permissive | — |
| `rand_chacha` | 0.3.1 | MIT OR Apache-2.0 | permissive | — |
| `rand_chacha` | 0.9.0 | MIT OR Apache-2.0 | permissive | — |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 | permissive | — |
| `rand_core` | 0.9.5 | MIT OR Apache-2.0 | permissive | — |
| `regex` | 1.12.3 | MIT OR Apache-2.0 | permissive | — |
| `regex-automata` | 0.4.14 | MIT OR Apache-2.0 | permissive | — |
| `regex-syntax` | 0.8.10 | MIT OR Apache-2.0 | permissive | — |
| `reqwest` | 0.12.28 | MIT OR Apache-2.0 | permissive | — |
| `resolv-conf` | 0.7.6 | MIT OR Apache-2.0 | permissive | — |
| `rfc6979` | 0.4.0 | Apache-2.0 OR MIT | permissive | — |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | permissive | — |
| `rsa` | 0.9.10 | MIT OR Apache-2.0 | permissive | — |
| `rustc-hash` | 2.1.2 | Apache-2.0 OR MIT | permissive | — |
| `rustc_version` | 0.4.1 | MIT OR Apache-2.0 | permissive | — |
| `rustls` | 0.23.40 | Apache-2.0 OR ISC OR MIT | permissive | — |
| `rustls-pki-types` | 1.14.1 | MIT OR Apache-2.0 | permissive | — |
| `rustls-webpki` | 0.103.13 | ISC | permissive | — |
| `rustversion` | 1.0.22 | MIT OR Apache-2.0 | permissive | — |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 | permissive | — |
| `scale-info` | 2.11.6 | Apache-2.0 | permissive | — |
| `scale-info-derive` | 2.11.6 | Apache-2.0 | permissive | — |
| `scopeguard` | 1.2.0 | MIT OR Apache-2.0 | permissive | — |
| `sec1` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `semver` | 1.0.28 | MIT OR Apache-2.0 | permissive | — |
| `serde` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde-human-bytes` | 0.1.2 | MIT OR Apache-2.0 | permissive | — |
| `serde-wasm-bindgen` | 0.6.5 | MIT | permissive | — |
| `serde_core` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde_derive` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde_json` | 1.0.149 | MIT OR Apache-2.0 | permissive | — |
| `serde_urlencoded` | 0.7.1 | MIT/Apache-2.0 | permissive | — |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | permissive | — |
| `shlex` | 1.3.0 | MIT OR Apache-2.0 | permissive | — |
| `signature` | 2.2.0 | Apache-2.0 OR MIT | permissive | — |
| `slab` | 0.4.12 | MIT | permissive | — |
| `smallvec` | 1.15.1 | MIT OR Apache-2.0 | permissive | — |
| `socket2` | 0.6.3 | MIT OR Apache-2.0 | permissive | — |
| `spin` | 0.9.9 | MIT | permissive | — |
| `spki` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | permissive | — |
| `strsim` | 0.11.1 | MIT | permissive | — |
| `subtle` | 2.6.1 | BSD-3-Clause | permissive | — |
| `syn` | 2.0.117 | MIT OR Apache-2.0 | permissive | — |
| `sync_wrapper` | 1.0.2 | Apache-2.0 | permissive | — |
| `synstructure` | 0.13.2 | MIT | permissive | — |
| `tagptr` | 0.2.0 | MIT/Apache-2.0 | permissive | — |
| `tap` | 1.0.1 | MIT | permissive | — |
| `thiserror` | 2.0.18 | MIT OR Apache-2.0 | permissive | — |
| `thiserror-impl` | 2.0.18 | MIT OR Apache-2.0 | permissive | — |
| `tinystr` | 0.8.3 | Unicode-3.0 | permissive | — |
| `tinyvec` | 1.11.0 | Zlib OR Apache-2.0 OR MIT | permissive | — |
| `tinyvec_macros` | 0.1.1 | MIT OR Apache-2.0 OR Zlib | permissive | — |
| `tokio` | 1.52.3 | MIT | permissive | — |
| `tokio-macros` | 2.7.0 | MIT | permissive | — |
| `tokio-rustls` | 0.26.4 | MIT OR Apache-2.0 | permissive | — |
| `toml_datetime` | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_edit` | 0.25.11+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_parser` | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `tower` | 0.5.3 | MIT | permissive | — |
| `tower-http` | 0.6.10 | MIT | permissive | — |
| `tower-layer` | 0.3.3 | MIT | permissive | — |
| `tower-service` | 0.3.3 | MIT | permissive | — |
| `tracing` | 0.1.44 | MIT | permissive | — |
| `tracing-attributes` | 0.1.31 | MIT | permissive | — |
| `tracing-core` | 0.1.36 | MIT | permissive | — |
| `try-lock` | 0.2.5 | MIT | permissive | — |
| `typenum` | 1.20.0 | MIT OR Apache-2.0 | permissive | — |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | permissive | — |
| `unicode-segmentation` | 1.13.2 | MIT OR Apache-2.0 | permissive | — |
| `unicode-xid` | 0.2.6 | MIT OR Apache-2.0 | permissive | — |
| `untrusted` | 0.9.0 | ISC | permissive | — |
| `url` | 2.5.8 | MIT OR Apache-2.0 | permissive | — |
| `urlencoding` | 2.1.3 | MIT | permissive | — |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT | permissive | — |
| `utf8parse` | 0.2.2 | Apache-2.0 OR MIT | permissive | — |
| `uuid` | 1.23.1 | Apache-2.0 OR MIT | permissive | — |
| `version_check` | 0.9.5 | MIT/Apache-2.0 | permissive | — |
| `want` | 0.3.1 | MIT | permissive | — |
| `wasm-bindgen` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-futures` | 0.4.68 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-macro` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-macro-support` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-shared` | 0.2.118 | MIT OR Apache-2.0 | permissive | — |
| `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| `webpki-roots` | 1.0.7 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| `winnow` | 1.0.3 | MIT | permissive | — |
| `writeable` | 0.6.3 | Unicode-3.0 | permissive | — |
| `wyz` | 0.5.1 | MIT | permissive | — |
| `x509-cert` | 0.2.5 | Apache-2.0 OR MIT | permissive | — |
| `yoke` | 0.8.2 | Unicode-3.0 | permissive | — |
| `yoke-derive` | 0.8.2 | Unicode-3.0 | permissive | — |
| `zerocopy` | 0.8.48 | BSD-2-Clause OR Apache-2.0 OR MIT | permissive | — |
| `zerofrom` | 0.1.8 | Unicode-3.0 | permissive | — |
| `zerofrom-derive` | 0.1.7 | Unicode-3.0 | permissive | — |
| `zeroize` | 1.8.2 | Apache-2.0 OR MIT | permissive | — |
| `zeroize_derive` | 1.4.3 | Apache-2.0 OR MIT | permissive | — |
| `zerotrie` | 0.2.4 | Unicode-3.0 | permissive | — |
| `zerovec` | 0.11.6 | Unicode-3.0 | permissive | — |
| `zerovec-derive` | 0.11.3 | Unicode-3.0 | permissive | — |
| `zmij` | 1.0.21 | MIT | permissive | — |

## Rust — `atlas-verify-cli`

Locked non-dev closure for `x86_64-unknown-linux-gnu` from `console/atlas-verify/Cargo.lock`. Builds the `umbra-atlas-verify` binary distributed inside the Console image.

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `aho-corasick` | 1.1.4 | Unlicense OR MIT | permissive | — |
| `anstream` | 1.0.0 | MIT OR Apache-2.0 | permissive | — |
| `anstyle` | 1.0.14 | MIT OR Apache-2.0 | permissive | — |
| `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 | permissive | — |
| `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 | permissive | — |
| `anyhow` | 1.0.102 | MIT OR Apache-2.0 | permissive | — |
| `arrayvec` | 0.7.7 | MIT OR Apache-2.0 | permissive | — |
| `asn1_der` | 0.7.7 | BSD-2-Clause OR MIT | permissive | — |
| `async-trait` | 0.1.89 | MIT OR Apache-2.0 | permissive | — |
| `atlas-rs` | 0.2.0 | MIT | permissive | — |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT | permissive | — |
| `autocfg` | 1.5.1 | Apache-2.0 OR MIT | permissive | — |
| `aws-lc-rs` | 1.17.0 | ISC AND (Apache-2.0 OR ISC) | permissive | — |
| `aws-lc-sys` | 0.41.0 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) | permissive | — |
| `base16ct` | 0.2.0 | Apache-2.0 OR MIT | permissive | — |
| `base64` | 0.13.1 | MIT/Apache-2.0 | permissive | — |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | permissive | — |
| `base64ct` | 1.8.3 | Apache-2.0 OR MIT | permissive | — |
| `bitflags` | 1.3.2 | MIT/Apache-2.0 | permissive | — |
| `bitflags` | 2.13.0 | MIT OR Apache-2.0 | permissive | — |
| `bitvec` | 1.1.1 | MIT | permissive | — |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 | permissive | — |
| `bon` | 3.9.3 | MIT OR Apache-2.0 | permissive | — |
| `bon-macros` | 3.9.3 | MIT OR Apache-2.0 | permissive | — |
| `borsh` | 1.7.0 | MIT OR Apache-2.0 | permissive | — |
| `borsh-derive` | 1.7.0 | Apache-2.0 | permissive | — |
| `bumpalo` | 3.20.3 | MIT OR Apache-2.0 | permissive | — |
| `byte-slice-cast` | 1.2.3 | MIT | permissive | — |
| `byteorder` | 1.5.0 | Unlicense OR MIT | permissive | — |
| `bytes` | 1.12.0 | MIT | permissive | — |
| `cc` | 1.2.65 | MIT OR Apache-2.0 | permissive | — |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | permissive | — |
| `cfg_aliases` | 0.2.1 | MIT | permissive | — |
| `chrono` | 0.4.45 | MIT OR Apache-2.0 | permissive | — |
| `cmake` | 0.1.58 | MIT OR Apache-2.0 | permissive | — |
| `colorchoice` | 1.0.5 | MIT OR Apache-2.0 | permissive | — |
| `const-oid` | 0.9.6 | Apache-2.0 OR MIT | permissive | — |
| `const_format` | 0.2.36 | Zlib | permissive | — |
| `const_format_proc_macros` | 0.2.34 | Zlib | permissive | — |
| `convert_case` | 0.10.0 | MIT | permissive | — |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 | permissive | — |
| `critical-section` | 1.2.0 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-channel` | 0.5.15 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-epoch` | 0.9.18 | MIT OR Apache-2.0 | permissive | — |
| `crossbeam-utils` | 0.8.21 | MIT OR Apache-2.0 | permissive | — |
| `crypto-bigint` | 0.5.5 | Apache-2.0 OR MIT | permissive | — |
| `crypto-common` | 0.1.6 | MIT OR Apache-2.0 | permissive | — |
| `curve25519-dalek` | 4.1.3 | BSD-3-Clause | permissive | — |
| `curve25519-dalek-derive` | 0.1.1 | MIT/Apache-2.0 | permissive | — |
| `darling` | 0.23.0 | MIT | permissive | — |
| `darling_core` | 0.23.0 | MIT | permissive | — |
| `darling_macro` | 0.23.0 | MIT | permissive | — |
| `data-encoding` | 2.11.0 | MIT | permissive | — |
| `dcap-qvl` | 0.3.12 | MIT | permissive | — |
| `dcap-qvl-webpki` | 0.103.4+dcap.1 | ISC | permissive | — |
| `defmt` | 1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `defmt-macros` | 1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `defmt-parser` | 1.0.0 | MIT OR Apache-2.0 | permissive | — |
| `der` | 0.7.10 | Apache-2.0 OR MIT | permissive | — |
| `der_derive` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `derive_more` | 1.0.0 | MIT | permissive | — |
| `derive_more` | 2.1.1 | MIT | permissive | — |
| `derive_more-impl` | 1.0.0 | MIT | permissive | — |
| `derive_more-impl` | 2.1.1 | MIT | permissive | — |
| `digest` | 0.10.7 | MIT OR Apache-2.0 | permissive | — |
| `displaydoc` | 0.2.6 | MIT OR Apache-2.0 | permissive | — |
| `dstack-sdk-types` | 0.1.3 | MIT | permissive | — |
| `dunce` | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 | permissive | — |
| `ecdsa` | 0.16.9 | Apache-2.0 OR MIT | permissive | — |
| `ed25519` | 2.2.3 | Apache-2.0 OR MIT | permissive | — |
| `ed25519-dalek` | 2.2.0 | BSD-3-Clause | permissive | — |
| `elliptic-curve` | 0.13.8 | Apache-2.0 OR MIT | permissive | — |
| `enum-as-inner` | 0.6.1 | MIT/Apache-2.0 | permissive | — |
| `env_filter` | 1.0.1 | MIT OR Apache-2.0 | permissive | — |
| `env_logger` | 0.11.10 | MIT OR Apache-2.0 | permissive | — |
| `equivalent` | 1.0.2 | Apache-2.0 OR MIT | permissive | — |
| `ff` | 0.13.1 | MIT/Apache-2.0 | permissive | — |
| `find-msvc-tools` | 0.1.9 | MIT OR Apache-2.0 | permissive | — |
| `flagset` | 0.4.7 | Apache-2.0 | permissive | — |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | permissive | — |
| `fs_extra` | 1.3.0 | MIT | permissive | — |
| `funty` | 2.0.0 | MIT | permissive | — |
| `futures` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-channel` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-core` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-executor` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-io` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-macro` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-sink` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-task` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `futures-util` | 0.3.32 | MIT OR Apache-2.0 | permissive | — |
| `generic-array` | 0.14.9 | MIT | permissive | — |
| `getrandom` | 0.2.17 | MIT OR Apache-2.0 | permissive | — |
| `getrandom` | 0.3.4 | MIT OR Apache-2.0 | permissive | — |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 | permissive | — |
| `group` | 0.13.0 | MIT/Apache-2.0 | permissive | — |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | permissive | — |
| `heck` | 0.5.0 | MIT OR Apache-2.0 | permissive | — |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | permissive | — |
| `hickory-proto` | 0.25.2 | MIT OR Apache-2.0 | permissive | — |
| `hickory-resolver` | 0.25.2 | MIT OR Apache-2.0 | permissive | — |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 | permissive | — |
| `http` | 1.4.2 | MIT OR Apache-2.0 | permissive | — |
| `http-body` | 1.0.1 | MIT | permissive | — |
| `http-body-util` | 0.1.3 | MIT | permissive | — |
| `httparse` | 1.10.1 | MIT OR Apache-2.0 | permissive | — |
| `hyper` | 1.10.1 | MIT | permissive | — |
| `hyper-rustls` | 0.27.9 | Apache-2.0 OR ISC OR MIT | permissive | — |
| `hyper-util` | 0.1.20 | MIT | permissive | — |
| `icu_collections` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_locale_core` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_normalizer` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_normalizer_data` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_properties` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_properties_data` | 2.2.0 | Unicode-3.0 | permissive | — |
| `icu_provider` | 2.2.0 | Unicode-3.0 | permissive | — |
| `ident_case` | 1.0.1 | MIT/Apache-2.0 | permissive | — |
| `idna` | 1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT | permissive | — |
| `impl-trait-for-tuples` | 0.2.3 | Apache-2.0/MIT | permissive | — |
| `indexmap` | 2.14.0 | Apache-2.0 OR MIT | permissive | — |
| `ipnet` | 2.12.0 | MIT OR Apache-2.0 | permissive | — |
| `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 | permissive | — |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 | permissive | — |
| `jiff` | 0.2.29 | Unlicense OR MIT | permissive | — |
| `jobserver` | 0.1.34 | MIT OR Apache-2.0 | permissive | — |
| `js-sys` | 0.3.102 | MIT OR Apache-2.0 | permissive | — |
| `konst` | 0.2.20 | Zlib | permissive | — |
| `konst_macro_rules` | 0.2.19 | Zlib | permissive | — |
| `lazy_static` | 1.5.0 | MIT OR Apache-2.0 | permissive | — |
| `libc` | 0.2.186 | MIT OR Apache-2.0 | permissive | — |
| `libm` | 0.2.16 | MIT | permissive | — |
| `litemap` | 0.8.2 | Unicode-3.0 | permissive | — |
| `lock_api` | 0.4.14 | MIT OR Apache-2.0 | permissive | — |
| `log` | 0.4.33 | MIT OR Apache-2.0 | permissive | — |
| `lru-slab` | 0.1.2 | MIT OR Apache-2.0 OR Zlib | permissive | — |
| `memchr` | 2.8.2 | Unlicense OR MIT | permissive | — |
| `mio` | 1.2.1 | MIT | permissive | — |
| `moka` | 0.12.15 | (MIT OR Apache-2.0) AND Apache-2.0 | permissive | — |
| `num-bigint-dig` | 0.8.6 | MIT/Apache-2.0 | permissive | — |
| `num-integer` | 0.1.46 | MIT OR Apache-2.0 | permissive | — |
| `num-iter` | 0.1.45 | MIT OR Apache-2.0 | permissive | — |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 | permissive | — |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 | permissive | — |
| `p256` | 0.13.2 | Apache-2.0 OR MIT | permissive | — |
| `p384` | 0.13.1 | Apache-2.0 OR MIT | permissive | — |
| `parity-scale-codec` | 3.7.5 | Apache-2.0 | permissive | — |
| `parity-scale-codec-derive` | 3.7.5 | Apache-2.0 | permissive | — |
| `parking_lot` | 0.12.5 | MIT OR Apache-2.0 | permissive | — |
| `parking_lot_core` | 0.9.12 | MIT OR Apache-2.0 | permissive | — |
| `pem` | 3.0.6 | MIT | permissive | — |
| `pem-rfc7468` | 0.7.0 | Apache-2.0 OR MIT | permissive | — |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 | permissive | — |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT | permissive | — |
| `pkcs1` | 0.7.5 | Apache-2.0 OR MIT | permissive | — |
| `pkcs8` | 0.10.2 | Apache-2.0 OR MIT | permissive | — |
| `portable-atomic` | 1.13.1 | Apache-2.0 OR MIT | permissive | — |
| `potential_utf` | 0.1.5 | Unicode-3.0 | permissive | — |
| `ppv-lite86` | 0.2.21 | MIT OR Apache-2.0 | permissive | — |
| `prettyplease` | 0.2.37 | MIT OR Apache-2.0 | permissive | — |
| `primeorder` | 0.13.6 | Apache-2.0 OR MIT | permissive | — |
| `proc-macro-crate` | 3.5.0 | MIT OR Apache-2.0 | permissive | — |
| `proc-macro-error-attr2` | 2.0.0 | MIT OR Apache-2.0 | permissive | — |
| `proc-macro-error2` | 2.0.1 | MIT OR Apache-2.0 | permissive | — |
| `proc-macro2` | 1.0.106 | MIT OR Apache-2.0 | permissive | — |
| `quinn` | 0.11.11 | MIT OR Apache-2.0 | permissive | — |
| `quinn-proto` | 0.11.15 | MIT OR Apache-2.0 | permissive | — |
| `quinn-udp` | 0.5.14 | MIT OR Apache-2.0 | permissive | — |
| `quote` | 1.0.46 | MIT OR Apache-2.0 | permissive | — |
| `radium` | 0.7.0 | MIT | permissive | — |
| `rand` | 0.8.6 | MIT OR Apache-2.0 | permissive | — |
| `rand` | 0.9.4 | MIT OR Apache-2.0 | permissive | — |
| `rand_chacha` | 0.3.1 | MIT OR Apache-2.0 | permissive | — |
| `rand_chacha` | 0.9.0 | MIT OR Apache-2.0 | permissive | — |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 | permissive | — |
| `rand_core` | 0.9.5 | MIT OR Apache-2.0 | permissive | — |
| `regex` | 1.12.4 | MIT OR Apache-2.0 | permissive | — |
| `regex-automata` | 0.4.14 | MIT OR Apache-2.0 | permissive | — |
| `regex-syntax` | 0.8.11 | MIT OR Apache-2.0 | permissive | — |
| `reqwest` | 0.12.28 | MIT OR Apache-2.0 | permissive | — |
| `resolv-conf` | 0.7.6 | MIT OR Apache-2.0 | permissive | — |
| `rfc6979` | 0.4.0 | Apache-2.0 OR MIT | permissive | — |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | permissive | — |
| `rsa` | 0.9.10 | MIT OR Apache-2.0 | permissive | — |
| `rustc-hash` | 2.1.2 | Apache-2.0 OR MIT | permissive | — |
| `rustc_version` | 0.4.1 | MIT OR Apache-2.0 | permissive | — |
| `rustls` | 0.23.41 | Apache-2.0 OR ISC OR MIT | permissive | — |
| `rustls-pki-types` | 1.14.1 | MIT OR Apache-2.0 | permissive | — |
| `rustls-webpki` | 0.103.13 | ISC | permissive | — |
| `rustversion` | 1.0.22 | MIT OR Apache-2.0 | permissive | — |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 | permissive | — |
| `scale-info` | 2.11.6 | Apache-2.0 | permissive | — |
| `scale-info-derive` | 2.11.6 | Apache-2.0 | permissive | — |
| `scopeguard` | 1.2.0 | MIT OR Apache-2.0 | permissive | — |
| `sec1` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `semver` | 1.0.28 | MIT OR Apache-2.0 | permissive | — |
| `serde` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde-human-bytes` | 0.1.3 | MIT OR Apache-2.0 | permissive | — |
| `serde-wasm-bindgen` | 0.6.5 | MIT | permissive | — |
| `serde_core` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde_derive` | 1.0.228 | MIT OR Apache-2.0 | permissive | — |
| `serde_json` | 1.0.150 | MIT OR Apache-2.0 | permissive | — |
| `serde_urlencoded` | 0.7.1 | MIT/Apache-2.0 | permissive | — |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | permissive | — |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 | permissive | — |
| `signature` | 2.2.0 | Apache-2.0 OR MIT | permissive | — |
| `slab` | 0.4.12 | MIT | permissive | — |
| `smallvec` | 1.15.2 | MIT OR Apache-2.0 | permissive | — |
| `socket2` | 0.6.4 | MIT OR Apache-2.0 | permissive | — |
| `spin` | 0.9.8 | MIT | permissive | — |
| `spki` | 0.7.3 | Apache-2.0 OR MIT | permissive | — |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | permissive | — |
| `strsim` | 0.11.1 | MIT | permissive | — |
| `subtle` | 2.6.1 | BSD-3-Clause | permissive | — |
| `syn` | 2.0.118 | MIT OR Apache-2.0 | permissive | — |
| `sync_wrapper` | 1.0.2 | Apache-2.0 | permissive | — |
| `synstructure` | 0.13.2 | MIT | permissive | — |
| `tagptr` | 0.2.0 | MIT/Apache-2.0 | permissive | — |
| `tap` | 1.0.1 | MIT | permissive | — |
| `thiserror` | 2.0.18 | MIT OR Apache-2.0 | permissive | — |
| `thiserror-impl` | 2.0.18 | MIT OR Apache-2.0 | permissive | — |
| `tinystr` | 0.8.3 | Unicode-3.0 | permissive | — |
| `tinyvec` | 1.11.0 | Zlib OR Apache-2.0 OR MIT | permissive | — |
| `tinyvec_macros` | 0.1.1 | MIT OR Apache-2.0 OR Zlib | permissive | — |
| `tokio` | 1.52.3 | MIT | permissive | — |
| `tokio-macros` | 2.7.0 | MIT | permissive | — |
| `tokio-rustls` | 0.26.4 | MIT OR Apache-2.0 | permissive | — |
| `toml_datetime` | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_edit` | 0.25.12+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `toml_parser` | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 | permissive | — |
| `tower` | 0.5.3 | MIT | permissive | — |
| `tower-http` | 0.6.11 | MIT | permissive | — |
| `tower-layer` | 0.3.3 | MIT | permissive | — |
| `tower-service` | 0.3.3 | MIT | permissive | — |
| `tracing` | 0.1.44 | MIT | permissive | — |
| `tracing-attributes` | 0.1.31 | MIT | permissive | — |
| `tracing-core` | 0.1.36 | MIT | permissive | — |
| `try-lock` | 0.2.5 | MIT | permissive | — |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 | permissive | — |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | permissive | — |
| `unicode-segmentation` | 1.13.3 | MIT OR Apache-2.0 | permissive | — |
| `unicode-xid` | 0.2.6 | MIT OR Apache-2.0 | permissive | — |
| `untrusted` | 0.9.0 | ISC | permissive | — |
| `url` | 2.5.8 | MIT OR Apache-2.0 | permissive | — |
| `urlencoding` | 2.1.3 | MIT | permissive | — |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT | permissive | — |
| `utf8parse` | 0.2.2 | Apache-2.0 OR MIT | permissive | — |
| `uuid` | 1.23.3 | Apache-2.0 OR MIT | permissive | — |
| `version_check` | 0.9.5 | MIT/Apache-2.0 | permissive | — |
| `want` | 0.3.1 | MIT | permissive | — |
| `wasm-bindgen` | 0.2.125 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-futures` | 0.4.75 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-macro` | 0.2.125 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-macro-support` | 0.2.125 | MIT OR Apache-2.0 | permissive | — |
| `wasm-bindgen-shared` | 0.2.125 | MIT OR Apache-2.0 | permissive | — |
| `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| `webpki-roots` | 1.0.8 | CDLA-Permissive-2.0 | non-OSI permissive | — |
| `winnow` | 1.0.3 | MIT | permissive | — |
| `writeable` | 0.6.3 | Unicode-3.0 | permissive | — |
| `wyz` | 0.5.1 | MIT | permissive | — |
| `x509-cert` | 0.2.5 | Apache-2.0 OR MIT | permissive | — |
| `yoke` | 0.8.3 | Unicode-3.0 | permissive | — |
| `yoke-derive` | 0.8.2 | Unicode-3.0 | permissive | — |
| `zerocopy` | 0.8.52 | BSD-2-Clause OR Apache-2.0 OR MIT | permissive | — |
| `zerofrom` | 0.1.8 | Unicode-3.0 | permissive | — |
| `zerofrom-derive` | 0.1.7 | Unicode-3.0 | permissive | — |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT | permissive | — |
| `zerotrie` | 0.2.4 | Unicode-3.0 | permissive | — |
| `zerovec` | 0.11.6 | Unicode-3.0 | permissive | — |
| `zerovec-derive` | 0.11.3 | Unicode-3.0 | permissive | — |
| `zmij` | 1.0.21 | MIT | permissive | — |

## Python — Console

Locked runtime closure of `umbra-console` from `console/uv.lock` (`uv sync --frozen --no-dev`, as the Console image installs it).

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `alembic` | 1.18.4 | MIT | permissive | — |
| `annotated-doc` | 0.0.4 | MIT | permissive | — |
| `annotated-types` | 0.7.0 | MIT | permissive | from trove classifiers |
| `anyio` | 4.13.0 | MIT | permissive | — |
| `asyncpg` | 0.31.0 | Apache-2.0 | permissive | — |
| `certifi` | 2026.4.22 | MPL-2.0 | weak copyleft | from trove classifiers |
| `cffi` | 2.0.0 | MIT | permissive | installed only when: platform_python_implementation != 'PyPy' |
| `click` | 8.3.3 | BSD-3-Clause | permissive | — |
| `colorama` | 0.4.6 | BSD-3-Clause | permissive | from trove classifiers — installed only when: sys_platform == 'win32' |
| `cryptography` | 48.0.0 | Apache-2.0 OR BSD-3-Clause | permissive | — |
| `fastapi` | 0.136.1 | MIT | permissive | — |
| `google-re2` | 1.1.20251105 | BSD-3-Clause | permissive | from trove classifiers |
| `greenlet` | 3.5.0 | MIT AND PSF-2.0 | permissive | installed only when: platform_machine == 'AMD64' or platform_machine == 'WIN32' or platform_machine == 'aarch64' or platform_machine == 'amd64' or platform_machine == 'ppc64le' or platform_machine == 'win32' or platform_machine == 'x86_64' |
| `h11` | 0.16.0 | MIT | permissive | from trove classifiers |
| `httpcore` | 1.0.9 | BSD-3-Clause | permissive | — |
| `httptools` | 0.7.1 | MIT | permissive | — |
| `httpx` | 0.28.1 | BSD-3-Clause | permissive | from trove classifiers |
| `idna` | 3.15 | BSD-3-Clause | permissive | — |
| `mako` | 1.3.12 | MIT | permissive | from trove classifiers |
| `markupsafe` | 3.0.3 | BSD-3-Clause | permissive | — |
| `pycparser` | 3.0 | BSD-3-Clause | permissive | installed only when: implementation_name != 'PyPy' |
| `pydantic` | 2.13.4 | MIT | permissive | — |
| `pydantic-core` | 2.46.4 | MIT | permissive | — |
| `pyjwt` | 2.12.1 | MIT | permissive | — |
| `python-dotenv` | 1.2.2 | BSD-3-Clause | permissive | from the prose `License` field |
| `pyyaml` | 6.0.3 | MIT | permissive | from trove classifiers |
| `sqlalchemy` | 2.0.49 | MIT | permissive | from the prose `License` field |
| `starlette` | 1.0.0 | BSD-3-Clause | permissive | — |
| `structlog` | 25.5.0 | MIT OR Apache-2.0 | permissive | — |
| `typing-extensions` | 4.15.0 | PSF-2.0 | permissive | — |
| `typing-inspection` | 0.4.2 | MIT | permissive | — |
| `uvicorn` | 0.47.0 | BSD-3-Clause | permissive | — |
| `uvloop` | 0.22.1 | Apache-2.0 AND MIT | permissive | from trove classifiers — installed only when: platform_python_implementation != 'PyPy' and sys_platform != 'cygwin' and sys_platform != 'win32' |
| `watchfiles` | 1.1.1 | MIT | permissive | from trove classifiers |
| `websockets` | 16.0 | BSD-3-Clause | permissive | — |

## Python — Security CVM

Locked runtime closure of `umbra-security-cvm` from `cvms/security/uv.lock` including the `mitmproxy` extra (`uv sync --frozen --no-dev --extra mitmproxy`, as the Security CVM image installs it).

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `aioquic` | 1.2.0 | BSD-3-Clause | permissive | from trove classifiers |
| `anyio` | 4.13.0 | MIT | permissive | — |
| `argon2-cffi` | 23.1.0 | MIT | permissive | from trove classifiers |
| `argon2-cffi-bindings` | 25.1.0 | MIT | permissive | — |
| `asgiref` | 3.8.1 | BSD-3-Clause | permissive | from trove classifiers |
| `attrs` | 26.1.0 | MIT | permissive | — |
| `blinker` | 1.9.0 | MIT | permissive | from trove classifiers |
| `brotli` | 1.1.0 | MIT | permissive | from trove classifiers |
| `certifi` | 2026.4.22 | MPL-2.0 | weak copyleft | from trove classifiers |
| `cffi` | 2.0.0 | MIT | permissive | — |
| `click` | 8.3.3 | BSD-3-Clause | permissive | — |
| `colorama` | 0.4.6 | BSD-3-Clause | permissive | from trove classifiers — installed only when: sys_platform == 'win32' |
| `cryptography` | 44.0.3 | Apache-2.0 AND BSD-3-Clause | permissive | from trove classifiers |
| `flask` | 3.1.0 | BSD-3-Clause | permissive | from trove classifiers |
| `google-re2` | 1.1.20251105 | BSD-3-Clause | permissive | from trove classifiers |
| `h11` | 0.14.0 | MIT | permissive | from trove classifiers |
| `h2` | 4.1.0 | MIT | permissive | from trove classifiers |
| `hpack` | 4.1.0 | MIT | permissive | from trove classifiers |
| `httpcore` | 1.0.8 | BSD-3-Clause | permissive | — |
| `httpx` | 0.28.1 | BSD-3-Clause | permissive | from trove classifiers |
| `hyperframe` | 6.1.0 | MIT | permissive | from trove classifiers |
| `idna` | 3.15 | BSD-3-Clause | permissive | — |
| `itsdangerous` | 2.2.0 | BSD-3-Clause | permissive | from trove classifiers |
| `jinja2` | 3.1.6 | BSD-3-Clause | permissive | from trove classifiers |
| `kaitaistruct` | 0.10 | MIT | permissive | from trove classifiers |
| `ldap3` | 2.9.1 | LGPL-3.0-only | weak copyleft | from trove classifiers |
| `markupsafe` | 3.0.3 | BSD-3-Clause | permissive | — |
| `mitmproxy` | 11.1.3 | MIT | permissive | from trove classifiers |
| `mitmproxy-linux` | 0.11.5 | MIT | permissive | from the prose `License` field — installed only when: sys_platform == 'linux' |
| `mitmproxy-macos` | 0.11.5 | MIT | permissive | installed only when: sys_platform == 'darwin' |
| `mitmproxy-rs` | 0.11.5 | MIT | permissive | from the prose `License` field |
| `mitmproxy-windows` | 0.11.5 | LGPL-3.0-or-later | weak copyleft | installed only when: os_name == 'nt' |
| `msgpack` | 1.1.0 | Apache-2.0 | permissive | from trove classifiers |
| `passlib` | 1.7.4 | BSD-3-Clause | permissive | from the prose `License` field |
| `publicsuffix2` | 2.20191221 | MIT AND MPL-2.0 | weak copyleft | from trove classifiers |
| `pyasn1` | 0.6.3 | BSD-2-Clause | permissive | from the prose `License` field |
| `pyasn1-modules` | 0.4.2 | BSD-3-Clause | permissive | from trove classifiers |
| `pycparser` | 3.0 | BSD-3-Clause | permissive | installed only when: implementation_name != 'PyPy' |
| `pydivert` | 2.1.0 | LGPL-3.0-or-later | weak copyleft | from trove classifiers — installed only when: sys_platform == 'win32' |
| `pylsqpack` | 0.3.24 | BSD-3-Clause | permissive | — |
| `pyopenssl` | 25.0.0 | Apache-2.0 | permissive | from trove classifiers |
| `pyparsing` | 3.2.1 | MIT | permissive | from trove classifiers |
| `pyperclip` | 1.9.0 | BSD-3-Clause | permissive | from trove classifiers |
| `ruamel-yaml` | 0.18.10 | MIT | permissive | from trove classifiers |
| `ruamel-yaml-clib` | 0.2.15 | MIT | permissive | from trove classifiers — installed only when: platform_python_implementation == 'CPython' |
| `service-identity` | 24.2.0 | MIT | permissive | from trove classifiers |
| `sortedcontainers` | 2.4.0 | Apache-2.0 | permissive | from trove classifiers |
| `tornado` | 6.4.2 | Apache-2.0 | permissive | from trove classifiers |
| `typing-extensions` | 4.15.0 | PSF-2.0 | permissive | — |
| `urwid` | 2.6.16 | LGPL-2.1-only | weak copyleft | from the prose `License` field |
| `wcwidth` | 0.7.0 | MIT | permissive | — |
| `werkzeug` | 3.1.8 | BSD-3-Clause | permissive | — |
| `wsproto` | 1.2.0 | MIT | permissive | from trove classifiers |
| `zstandard` | 0.23.0 | BSD-3-Clause | permissive | from trove classifiers |

## npm — Console runtime (`phala` CLI)

Non-dev entries of `console/package-lock.json`. The Console image retains this graph after `npm prune --omit=dev`; the Console shells out to the pinned Phala CLI through its provider adapter.

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `@adraffy/ens-normalize` | 1.11.1 | MIT | permissive | — |
| `@iarna/toml` | 2.2.5 | ISC | permissive | — |
| `@inquirer/ansi` | 1.0.2 | MIT | permissive | — |
| `@inquirer/checkbox` | 4.3.2 | MIT | permissive | — |
| `@inquirer/confirm` | 5.1.21 | MIT | permissive | — |
| `@inquirer/core` | 10.3.2 | MIT | permissive | — |
| `@inquirer/core/node_modules/signal-exit` | 4.1.0 | ISC | permissive | — |
| `@inquirer/editor` | 4.2.23 | MIT | permissive | — |
| `@inquirer/expand` | 4.0.23 | MIT | permissive | — |
| `@inquirer/external-editor` | 1.0.3 | MIT | permissive | — |
| `@inquirer/figures` | 1.0.15 | MIT | permissive | — |
| `@inquirer/input` | 4.3.1 | MIT | permissive | — |
| `@inquirer/number` | 3.0.23 | MIT | permissive | — |
| `@inquirer/password` | 4.0.23 | MIT | permissive | — |
| `@inquirer/prompts` | 7.10.1 | MIT | permissive | — |
| `@inquirer/rawlist` | 4.1.11 | MIT | permissive | — |
| `@inquirer/search` | 3.2.2 | MIT | permissive | — |
| `@inquirer/select` | 4.4.2 | MIT | permissive | — |
| `@inquirer/type` | 3.0.10 | MIT | permissive | — |
| `@michaelhomer/jqjs` | 1.6.0 | MIT | permissive | — |
| `@noble/ciphers` | 1.3.0 | MIT | permissive | — |
| `@noble/curves` | 1.9.7 | MIT | permissive | — |
| `@noble/hashes` | 1.8.0 | MIT | permissive | — |
| `@nodelib/fs.scandir` | 2.1.5 | MIT | permissive | — |
| `@nodelib/fs.stat` | 2.0.5 | MIT | permissive | — |
| `@nodelib/fs.walk` | 1.2.8 | MIT | permissive | — |
| `@phala/cloud` | 0.2.10 | Apache-2.0 | permissive | — |
| `@phala/dstack-sdk` | 0.5.8 | Apache-2.0 | permissive | — |
| `@scure/base` | 1.2.6 | MIT | permissive | — |
| `@scure/bip32` | 1.7.0 | MIT | permissive | — |
| `@scure/bip39` | 1.6.0 | MIT | permissive | — |
| `@types/node` | 25.8.0 | MIT | permissive | from the npm registry manifest |
| `abitype` | 1.2.3 | MIT | permissive | — |
| `ansi-regex` | 6.2.2 | MIT | permissive | — |
| `ansi-styles` | 4.3.0 | MIT | permissive | — |
| `arg` | 5.0.2 | MIT | permissive | — |
| `base64-js` | 1.5.1 | MIT | permissive | — |
| `bl` | 5.1.0 | MIT | permissive | — |
| `bl/node_modules/readable-stream` | 3.6.2 | MIT | permissive | — |
| `braces` | 3.0.3 | MIT | permissive | — |
| `buffer` | 6.0.3 | MIT | permissive | — |
| `bufferutil` | 4.1.0 | MIT | permissive | — |
| `bundle-name` | 4.1.0 | MIT | permissive | — |
| `chalk` | 5.2.0 | MIT | permissive | — |
| `chardet` | 2.1.1 | MIT | permissive | — |
| `cli-cursor` | 4.0.0 | MIT | permissive | — |
| `cli-spinners` | 2.9.2 | MIT | permissive | — |
| `cli-width` | 4.1.0 | ISC | permissive | — |
| `clone` | 1.0.4 | MIT | permissive | — |
| `color-convert` | 2.0.1 | MIT | permissive | — |
| `color-name` | 1.1.4 | MIT | permissive | — |
| `cross-spawn` | 7.0.6 | MIT | permissive | — |
| `debug` | 4.4.3 | MIT | permissive | — |
| `dedent` | 1.7.2 | MIT | permissive | — |
| `default-browser` | 5.5.0 | MIT | permissive | — |
| `default-browser-id` | 5.0.1 | MIT | permissive | — |
| `defaults` | 1.0.4 | MIT | permissive | — |
| `define-lazy-prop` | 3.0.0 | MIT | permissive | — |
| `destr` | 2.0.5 | MIT | permissive | — |
| `emoji-regex` | 8.0.0 | MIT | permissive | — |
| `eventemitter3` | 5.0.1 | MIT | permissive | — |
| `execa` | 7.2.0 | MIT | permissive | — |
| `fast-glob` | 3.3.3 | MIT | permissive | — |
| `fastq` | 1.20.1 | ISC | permissive | — |
| `fill-range` | 7.1.1 | MIT | permissive | — |
| `fs-extra` | 11.3.5 | MIT | permissive | — |
| `get-stream` | 6.0.1 | MIT | permissive | — |
| `glob-parent` | 5.1.2 | ISC | permissive | — |
| `graceful-fs` | 4.2.11 | ISC | permissive | — |
| `handlebars` | 4.7.9 | MIT | permissive | — |
| `human-signals` | 4.3.1 | Apache-2.0 | permissive | — |
| `iconv-lite` | 0.7.2 | MIT | permissive | — |
| `ieee754` | 1.2.1 | BSD-3-Clause | permissive | — |
| `inherits` | 2.0.4 | ISC | permissive | — |
| `inquirer` | 12.11.1 | MIT | permissive | — |
| `is-docker` | 3.0.0 | MIT | permissive | — |
| `is-extglob` | 2.1.1 | MIT | permissive | — |
| `is-fullwidth-code-point` | 3.0.0 | MIT | permissive | — |
| `is-glob` | 4.0.3 | MIT | permissive | — |
| `is-inside-container` | 1.0.0 | MIT | permissive | — |
| `is-interactive` | 2.0.0 | MIT | permissive | — |
| `is-number` | 7.0.0 | MIT | permissive | — |
| `is-stream` | 3.0.0 | MIT | permissive | — |
| `is-unicode-supported` | 1.3.0 | MIT | permissive | — |
| `is-wsl` | 3.1.1 | MIT | permissive | — |
| `isexe` | 2.0.0 | ISC | permissive | — |
| `isows` | 1.0.7 | MIT | permissive | — |
| `jsonfile` | 6.2.1 | MIT | permissive | — |
| `kleur` | 3.0.3 | MIT | permissive | — |
| `log-symbols` | 5.1.0 | MIT | permissive | — |
| `merge-stream` | 2.0.0 | MIT | permissive | — |
| `merge2` | 1.4.1 | MIT | permissive | — |
| `micromatch` | 4.0.8 | MIT | permissive | — |
| `mimic-fn` | 4.0.0 | MIT | permissive | — |
| `minimist` | 1.2.8 | MIT | permissive | — |
| `mitt` | 3.0.1 | MIT | permissive | — |
| `ms` | 2.1.3 | MIT | permissive | — |
| `mute-stream` | 2.0.0 | ISC | permissive | — |
| `neo-async` | 2.6.2 | MIT | permissive | — |
| `node-fetch-native` | 1.6.7 | MIT | permissive | — |
| `node-gyp-build` | 4.8.4 | MIT | permissive | — |
| `npm-run-path` | 5.3.0 | MIT | permissive | — |
| `npm-run-path/node_modules/path-key` | 4.0.0 | MIT | permissive | — |
| `ofetch` | 1.5.1 | MIT | permissive | — |
| `onetime` | 6.0.0 | MIT | permissive | — |
| `open` | 10.2.0 | MIT | permissive | — |
| `ora` | 6.3.1 | MIT | permissive | — |
| `ox` | 0.14.33 | MIT | permissive | — |
| `ox/node_modules/@noble/curves` | 1.9.1 | MIT | permissive | — |
| `path-key` | 3.1.1 | MIT | permissive | — |
| `phala` | 1.1.19 | Apache-2.0 | permissive | — |
| `picomatch` | 2.3.2 | MIT | permissive | — |
| `prompts` | 2.4.2 | MIT | permissive | — |
| `queue-microtask` | 1.2.3 | MIT | permissive | — |
| `restore-cursor` | 4.0.0 | MIT | permissive | — |
| `restore-cursor/node_modules/mimic-fn` | 2.1.0 | MIT | permissive | — |
| `restore-cursor/node_modules/onetime` | 5.1.2 | MIT | permissive | — |
| `reusify` | 1.1.0 | MIT | permissive | — |
| `run-applescript` | 7.1.0 | MIT | permissive | — |
| `run-async` | 4.0.6 | MIT | permissive | — |
| `run-parallel` | 1.2.0 | MIT | permissive | — |
| `rxjs` | 7.8.2 | Apache-2.0 | permissive | — |
| `safer-buffer` | 2.1.2 | MIT | permissive | — |
| `semver` | 7.8.0 | ISC | permissive | — |
| `shebang-command` | 2.0.0 | MIT | permissive | — |
| `shebang-regex` | 3.0.0 | MIT | permissive | — |
| `signal-exit` | 3.0.7 | ISC | permissive | — |
| `sisteransi` | 1.0.5 | MIT | permissive | — |
| `source-map` | 0.6.1 | BSD-3-Clause | permissive | — |
| `stdin-discarder` | 0.1.0 | MIT | permissive | — |
| `string-width` | 4.2.3 | MIT | permissive | — |
| `string-width/node_modules/ansi-regex` | 5.0.1 | MIT | permissive | — |
| `string-width/node_modules/strip-ansi` | 6.0.1 | MIT | permissive | — |
| `string_decoder` | 1.1.1 | MIT | permissive | — |
| `string_decoder/node_modules/safe-buffer` | 5.1.2 | MIT | permissive | — |
| `strip-ansi` | 7.2.0 | MIT | permissive | — |
| `strip-final-newline` | 3.0.0 | MIT | permissive | — |
| `to-regex-range` | 5.0.1 | MIT | permissive | — |
| `tslib` | 2.8.1 | 0BSD | permissive | — |
| `typescript` | 6.0.3 | Apache-2.0 | permissive | — |
| `ufo` | 1.6.4 | MIT | permissive | — |
| `uglify-js` | 3.19.3 | BSD-2-Clause | permissive | — |
| `undici-types` | 7.24.6 | MIT | permissive | from the npm registry manifest |
| `universalify` | 2.0.1 | MIT | permissive | — |
| `utf-8-validate` | 5.0.10 | MIT | permissive | — |
| `util-deprecate` | 1.0.2 | MIT | permissive | — |
| `viem` | 2.55.10 | MIT | permissive | — |
| `viem/node_modules/@noble/curves` | 1.9.1 | MIT | permissive | — |
| `wcwidth` | 1.0.1 | MIT | permissive | — |
| `which` | 2.0.2 | ISC | permissive | — |
| `wordwrap` | 1.0.0 | MIT | permissive | — |
| `wrap-ansi` | 6.2.0 | MIT | permissive | — |
| `wrap-ansi/node_modules/ansi-regex` | 5.0.1 | MIT | permissive | — |
| `wrap-ansi/node_modules/strip-ansi` | 6.0.1 | MIT | permissive | — |
| `ws` | 8.21.0 | MIT | permissive | — |
| `wsl-utils` | 0.1.0 | MIT | permissive | — |
| `yoctocolors-cjs` | 2.1.3 | MIT | permissive | — |
| `zod` | 3.25.76 | MIT | permissive | — |

## npm — dashboard build graph (build-time only)

**Build-time only — not distributed.** Dev-only entries of `console/package-lock.json`: the Tailwind graph that compiles `console/static/admin/tailwind.in.css` into `tailwind.css` in the isolated `webapp-builder` stage. `npm prune --omit=dev` removes every package below before the runtime stage copies `node_modules`, so none of it ships in the Console image. Listed for build-input transparency (OSS-07).

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `@alloc/quick-lru` | 5.2.0 | MIT | permissive | — |
| `@jridgewell/gen-mapping` | 0.3.13 | MIT | permissive | — |
| `@jridgewell/resolve-uri` | 3.1.2 | MIT | permissive | — |
| `@jridgewell/sourcemap-codec` | 1.5.5 | MIT | permissive | — |
| `@jridgewell/trace-mapping` | 0.3.31 | MIT | permissive | — |
| `any-promise` | 1.3.0 | MIT | permissive | — |
| `anymatch` | 3.1.3 | ISC | permissive | — |
| `binary-extensions` | 2.3.0 | MIT | permissive | — |
| `camelcase-css` | 2.0.1 | MIT | permissive | — |
| `chokidar` | 3.6.0 | MIT | permissive | — |
| `cssesc` | 3.0.0 | MIT | permissive | — |
| `didyoumean` | 1.2.2 | Apache-2.0 | permissive | — |
| `dlv` | 1.1.3 | MIT | permissive | — |
| `es-errors` | 1.3.0 | MIT | permissive | — |
| `fsevents` | 2.3.3 | MIT | permissive | — |
| `function-bind` | 1.1.2 | MIT | permissive | — |
| `hasown` | 2.0.3 | MIT | permissive | — |
| `is-binary-path` | 2.1.0 | MIT | permissive | — |
| `is-core-module` | 2.16.2 | MIT | permissive | — |
| `jiti` | 1.21.7 | MIT | permissive | — |
| `lilconfig` | 2.1.0 | MIT | permissive | — |
| `lines-and-columns` | 1.2.4 | MIT | permissive | — |
| `mz` | 2.7.0 | MIT | permissive | — |
| `nanoid` | 3.3.17 | MIT | permissive | — |
| `normalize-path` | 3.0.0 | MIT | permissive | — |
| `object-assign` | 4.1.1 | MIT | permissive | — |
| `object-hash` | 3.0.0 | MIT | permissive | — |
| `path-parse` | 1.0.7 | MIT | permissive | — |
| `picocolors` | 1.1.1 | ISC | permissive | — |
| `pify` | 2.3.0 | MIT | permissive | — |
| `pirates` | 4.0.7 | MIT | permissive | — |
| `postcss` | 8.5.25 | MIT | permissive | — |
| `postcss-import` | 15.1.0 | MIT | permissive | — |
| `postcss-js` | 4.1.0 | MIT | permissive | — |
| `postcss-load-config` | 4.0.2 | MIT | permissive | — |
| `postcss-load-config/node_modules/lilconfig` | 3.1.3 | MIT | permissive | — |
| `postcss-nested` | 6.2.0 | MIT | permissive | — |
| `postcss-selector-parser` | 6.1.4 | MIT | permissive | — |
| `postcss-value-parser` | 4.2.0 | MIT | permissive | — |
| `read-cache` | 1.0.0 | MIT | permissive | — |
| `readdirp` | 3.6.0 | MIT | permissive | — |
| `resolve` | 1.22.12 | MIT | permissive | — |
| `source-map-js` | 1.2.1 | BSD-3-Clause | permissive | — |
| `sucrase` | 3.35.1 | MIT | permissive | — |
| `sucrase/node_modules/commander` | 4.1.1 | MIT | permissive | — |
| `supports-preserve-symlinks-flag` | 1.0.0 | MIT | permissive | — |
| `tailwindcss` | 3.4.13 | MIT | permissive | — |
| `tailwindcss/node_modules/glob-parent` | 6.0.2 | ISC | permissive | — |
| `thenify` | 3.3.1 | MIT | permissive | — |
| `thenify-all` | 1.6.0 | MIT | permissive | — |
| `tinyglobby` | 0.2.17 | MIT | permissive | — |
| `tinyglobby/node_modules/fdir` | 6.5.0 | MIT | permissive | — |
| `tinyglobby/node_modules/picomatch` | 4.0.5 | MIT | permissive | — |
| `ts-interface-checker` | 0.1.13 | Apache-2.0 | permissive | — |
| `yaml` | 2.9.0 | ISC | permissive | — |

## npm — Codex (Dev CVM image)

`cvms/dev/user-sandbox/codex-package/package-lock.json`, installed into the Dev CVM image with `npm ci --omit=dev`. Only the `linux-x64` optional platform package is installed at build time; every platform package is listed because the lock pins them all.

| Package | Version | Declared license | Category | Note |
| --- | --- | --- | --- | --- |
| `@openai/codex` | 0.131.0 | Apache-2.0 | permissive | — |
| `@openai/codex` | 0.131.0-darwin-arm64 | Apache-2.0 | permissive | — |
| `@openai/codex` | 0.131.0-darwin-x64 | Apache-2.0 | permissive | — |
| `@openai/codex` | 0.131.0-linux-arm64 | Apache-2.0 | permissive | — |
| `@openai/codex` | 0.131.0-linux-x64 | Apache-2.0 | permissive | — |
| `@openai/codex` | 0.131.0-win32-arm64 | Apache-2.0 | permissive | — |
| `@openai/codex` | 0.131.0-win32-x64 | Apache-2.0 | permissive | — |

<!-- END GENERATED INVENTORY -->

## Baked developer agents in the Dev CVM image

- **Codex** (`@openai/codex` 0.131.0, Apache-2.0). Installed into the image from the reviewed, locked package under `cvms/dev/user-sandbox/codex-package/` with `npm ci --omit=dev`; the package's `LICENSE` ships inside the installed `node_modules` tree, which satisfies the Apache-2.0 redistribution condition, and this file provides the corresponding notice entry. The version above is the baked build-time pin; `umbra-update-agents.sh` may update the installed copy in a running sandbox, so the shipped image states the baked version, not a runtime guarantee.
- **Claude Code** (2.1.144, proprietary — Anthropic). Baked from the upstream release tarball with a SHA-256 pin. The project does not redistribute this binary: the Dev CVM image is not published for anonymous pull (ADR 0005 amendment, 2026-08-05), and a self-hoster's own image build downloads it directly from Anthropic's release URL. The same runtime-update caveat applies.

## Image system components and base images

Components installed into the container images (all version- and digest-/SHA-256-pinned in the Dockerfiles and `tool-versions.env`):

| Component | Where | License | Obligation and how it is satisfied |
| --- | --- | --- | --- |
| Ubuntu 24.04 base + snapshot APT packages | Dev CVM image | Various (see Ubuntu per-package copyright files) | Package copyright files ship in the image under `/usr/share/doc/*/copyright`; no source-offer obligation is triggered by unmodified binary redistribution of the archive packages. |
| Debian (python:3.12-slim base) | Console, Security CVM images | Various (Debian per-package copyright files) | Same as above; copyright files retained in-image. |
| Alpine base | Installer, reverse-proxy images | Various (mostly MIT/BSD; apk metadata) | Pinned complete package closure; license metadata retained by apk. |
| Python 3.12 | Console, Security CVM images | PSF-2.0 | Permissive; retained upstream image layers unmodified. |
| Docker Engine, CLI, containerd, Buildx, Compose plugin | Dev CVM image | Apache-2.0 | Unmodified official `.deb`s (SHA-256-pinned); Apache-2.0 license/notice files ship in the packages; noticed here. |
| GitHub CLI (`gh` 2.92.0) | Dev CVM image | MIT | License text ships in the upstream release tarball layout and package docs; noticed here. |
| Node.js (22.22.3) | Dev CVM image | MIT (plus bundled component licenses) | Upstream tarball retains its `LICENSE` at the install prefix; noticed here. |
| uv | All Python images (build stage) and Dev CVM image | Apache-2.0 OR MIT | Permissive dual license; binary copied from the digest-pinned upstream image; noticed here. |
| nginx (1.27-alpine) | Reverse-proxy image | BSD-2-Clause | Permissive; unmodified official image; noticed here. |
| mitmproxy (11.x) | Security CVM image | MIT (dependency graph inventoried above) | Installed from the locked `mitmproxy` extra; per-package obligations covered by the generated inventory. |
| PostgreSQL (postgres:16) | Compose deployment (pulled by the operator, not redistributed by Umbra) | PostgreSQL License | Referenced by digest in `docker-compose.yml`; the operator pulls the official image directly, so Umbra redistributes nothing. |

## Maintainer review queue

Flagged rows from the generated inventory, with disposition context. **Decision (2026-08-05, owner/legal): all entries below are accepted as-is** — see the approval record in the private archive.

- **`webpki-roots` (CDLA-Permissive-2.0)** — Rust, all three binaries. A permissive data license for the bundled Mozilla root-certificate store; not OSI-listed, but redistribution with attribution is allowed. Needs a one-time maintainer/legal acknowledgment.
- **`certifi` (MPL-2.0)** — Console and Security CVM. Weak file-level copyleft covering only the unmodified `cacert.pem`/module itself; obligations are met by shipping it unmodified from PyPI. Needs acknowledgment, no code impact.
- **`publicsuffix2` (MIT AND MPL-2.0)** — Security CVM (mitmproxy dependency). Same MPL-2.0 posture as `certifi`: unmodified redistribution.
- **`urwid` (LGPL-2.1-only)** and **`ldap3` (LGPL-3.0-only)** — Security CVM, transitive dependencies of mitmproxy, installed on the Linux image. Both are dynamically imported pure-Python libraries used unmodified, which is the standard LGPL-compliant posture for Python packages; source is available from PyPI at the locked versions. Needs maintainer/legal acknowledgment.
- **`pydivert` (LGPL-3.0-or-later)** and **`mitmproxy-windows` (LGPL-3.0-or-later)** — Windows-only (`sys_platform == 'win32'` / `os_name == 'nt'` markers in `cvms/security/uv.lock`); they appear in the lock but are **never installed** in the Linux Security CVM image, so no redistribution obligation attaches to shipped artifacts.
- The historical `rpc-websockets` copyleft lead is absent from the current tree and all lockfiles.
