# Attestation Service

A FastAPI-based service that provides Intel TDX attestations.

The attestation service exposes REST API endpoints that allow clients to:

- Get cryptographic quotes containing attestation evidence
- Verify the integrity and authenticity of confidential computing environments
- Provide proof that code is running within a trusted execution environment

Behind the scenes, the service uses the `dstack_sdk` to communicate with the dstack daemon via Unix socket (`/var/run/dstack.sock`), which in turn handles the interaction with TDX hardware to generate attestation quotes that can be verified by remote parties.

## API Endpoints

- `GET /health` - Service health check
- `POST /tdx_quote` - Generate TDX attestation quote with custom report data

You also have API docs at `/docs` and `/redoc`.

## Requirements

This service uses [uv](https://docs.astral.sh/uv/) for Python dependency management and virtual environment management. `uv` provides fast, reliable package resolution and installation.

## Usage

See the `Makefile` for common operations:

### Environment Configuration

- **NO_TDX=true** (default): Runs without Dstack socket binding for development/testing
- **NO_TDX=false**: Enables TDX hardware integration by binding to `/var/run/dstack.sock`

### Examples

```bash
# Development mode
make dev

# Production with TDX hardware
NO_TDX=false make run

# Full test suite
make all
```
