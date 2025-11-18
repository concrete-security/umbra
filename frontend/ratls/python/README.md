# python (PyO3 binding)

Python wrapper exposing async `connect(host, port, policy, tunnel=None)` that returns a channel with `send/recv/close` and `attestation()` accessors.

## Responsibilities
- Direct TCP by default; optional tunnel transport for constrained egress.
- Align policy/attestation result schema with other bindings.
- Provide asyncio-friendly interface and type hints.

## Next steps
- Create PyO3 project scaffold, maturin build config, and minimal integration tests against mocks.
- Add tox/pytest wiring once core pieces exist.
