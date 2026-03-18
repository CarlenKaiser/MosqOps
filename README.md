# MosqOps

MosqOps is a Rust-based Mosquitto plugin that embeds an HTTP API for broker operations.

It is designed to pair with Mosquitto Dynamic Security, giving you REST endpoints to:

- Read and update broker config (`mosquitto.conf`)
- Manage dynamic security entities (clients, roles, groups, ACLs)
- Read and stream broker logs
- Trigger broker restart workflows

## What This Plugin Does

At plugin initialization, MosqOps:

- Starts a background Tokio runtime
- Boots an Axum HTTP server on `0.0.0.0:8080`
- Connects to Mosquitto's dynamic security control topics over MQTT
- Creates "working" backup copies of broker config files for reset safety

Operationally, it combines two paths:

1. Real-time commands through `$CONTROL/dynamic-security/v1`
2. File persistence updates to the dynamic security JSON for restart resilience

## Key Features

- Embedded HTTP API with health and status routes
- Broker config read/update/reset with syntax validation
- Dynamic security management for clients, roles, groups, and ACLs
- Broker log tail and SSE stream endpoints
- Optional wildcard-subscription policy enforcement

## Architecture Notes

- HTTP server: Axum on port `8080`
- Internal coordinator: MQTT client to broker at `127.0.0.1:1883`
- Dynamic security command topics:
  - Request: `$CONTROL/dynamic-security/v1`
  - Response: `$CONTROL/dynamic-security/v1/response`
- Plugin API version reported to Mosquitto: `5`

## Endpoint Reference

Full endpoint details are in [docs/API.md](docs/API.md).

### Core routes

- `GET /api/v1/health`
- `GET /api/status`
- `GET /api/config`
- `POST /api/config`
- `POST /api/config/reset`
- `POST /api/restart`

### Dynamic security routes

- Clients: `/api/v1/clients...`
- Roles: `/api/v1/roles...`
- Groups: `/api/v1/groups...`
- DynSec file: `/api/v1/config/dynsec...`

### Log routes

- `GET /api/v1/logs/broker`
- `GET /api/v1/logs/stream` (SSE)

## Configuration

### Plugin options

MosqOps reads plugin options passed by Mosquitto:

- `conf_path`: broker config path
- `config_file`: dynamic security JSON path fallback

The plugin also resolves dynsec path from `plugin_opt_config_file` inside the broker config when available.

### Environment variables

- `DYNSEC_PATH`: force dynsec JSON path (highest precedence)
- `MOSQUITTO_ADMIN_USERNAME`: optional internal MQTT username
- `MOSQUITTO_ADMIN_PASSWORD`: optional internal MQTT password
- `MOSQOPS_ALLOW_WILDCARD_SUBS`:
  - default behavior: wildcard subscriptions are enabled
  - set to `0`, `false`, or `no` to disable that auto-enforcement

## Quick Start

### 1. Build the plugin

Windows (local):

```bat
compile.bat
```

Cross-build in container (produces `.so` carrier artifact):

```powershell
docker build -f Dockerfile.carrier -t mosqops-carrier .
```

### 2. Configure Mosquitto to load the plugin

Example snippet:

```conf
plugin /path/to/mosqops.so
plugin_opt_conf_path /path/to/mosquitto.conf
plugin_opt_config_file /path/to/dynamic-security.json

listener 1883
```

For a local test baseline, see `test.conf`.

### 3. Start Mosquitto

Start broker with your config; MosqOps starts the API as part of plugin init.

### 4. Verify API

```bash
curl http://localhost:8080/api/v1/health
```

Expected response:

```text
OK
```

## Usage Examples

Create a dynamic security client:

```bash
curl -X POST http://localhost:8080/api/v1/clients \
  -H "Content-Type: application/json" \
  -d '{"username":"sensor-01","password":"change-me"}'
```

List roles:

```bash
curl http://localhost:8080/api/v1/roles
```

Update broker config:

```bash
curl -X POST http://localhost:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"mosquitto_conf":"listener 1883\nallow_anonymous false"}'
```

## Production Considerations

- The HTTP API currently has no built-in authentication.
- Expose port `8080` only on trusted networks, or place it behind an authenticated reverse proxy.
- Backups are written as `*.working` files; include these in your operational backup model.
- Several log/reload operations assume Linux process and tool behavior (`tail`, `sh`, `kill -HUP`).

## Repository Layout

- `src/`: main MosqOps plugin implementation
- `mosquitto-plugin-local/`: local Rust dependency for Mosquitto plugin bindings
- `include/`: Mosquitto headers used for bindgen and builds
- `Dockerfile.carrier`: multi-stage build for carrier image
- `build-carrier.ps1`: build and push image helper

## Build And Publish Helper

The helper script can build and push a carrier image:

```powershell
.\build-carrier.ps1 -Registry <your-registry.azurecr.io> -Tag <version>
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please read [SECURITY.md](SECURITY.md) before reporting vulnerabilities.

## Code Of Conduct

This project follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
