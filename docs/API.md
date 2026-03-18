# MosqOps HTTP API

Base URL: `http://<host>:8080`

## Notes

- Responses are currently mixed: some endpoints return JSON, others return plain text.
- There is no built-in authentication layer in this API.
- Most dynamic-security operations proxy Mosquitto dynsec commands and then trigger a manual JSON persistence sync.

## Health And Status

### GET /api/v1/health

Returns simple liveness text.

Response:

```text
OK
```

### GET /api/status

Returns whether a broker restart is pending.

Response example:

```json
{
  "pending_restart": false
}
```

## Broker Config

### GET /api/config

Reads and parses `mosquitto.conf`.

Response includes:

- `success`
- `config` (top-level directives)
- `listeners` (parsed listener directives)
- `listener` (legacy compatibility mirror)
- `mosquitto_conf` (raw file text)

### POST /api/config

Updates broker config after syntax validation using `mosquitto -test`.

Request body supports either:

- `mosquitto_conf` (preferred)
- `config_content` (backward compatibility)

Example request:

```json
{
  "mosquitto_conf": "listener 1883\nallow_anonymous false"
}
```

Success response:

```json
{
  "message": "Configuration successfully validated and updated.",
  "status": "ok"
}
```

### POST /api/config/reset

Restores `mosquitto.conf` from `<conf_path>.working`.

Success response:

```json
{
  "message": "Configuration successfully restored to the last known working state.",
  "status": "ok"
}
```

### POST /api/restart

Triggers delayed process termination (`exit(0)`) so a service manager can restart broker/plugin.

Response:

```json
{
  "message": "Restart triggered. Broker is terminating.",
  "status": "ok"
}
```

## Dynamic Security Config File

### GET /api/v1/config/dynsec

Returns parsed dynamic security JSON.

### PUT /api/v1/config/dynsec

Replaces dynamic security JSON content.

- Optional wildcard subscription enforcement may rewrite roles/clients with `allowwildcardsubs: true`.
- Sends `SIGHUP` to PID 1 after write.

Request body: arbitrary JSON payload.

### POST /api/v1/config/dynsec/reset

Restores dynsec file from `<dynsec_path>.working` and sends `SIGHUP`.

## Clients

### POST /api/v1/clients

Create client.

Request:

```json
{
  "username": "clientA",
  "password": "secret"
}
```

### GET /api/v1/clients

List clients (plain text response).

### GET /api/v1/clients/:username

Get one client (plain text response).

### DELETE /api/v1/clients/:username

Delete client.

### PUT /api/v1/clients/:username/password

Set password.

Request:

```json
{
  "username": "ignored-by-path",
  "password": "new-secret"
}
```

### PUT /api/v1/clients/:username/enable

Enable client.

### PUT /api/v1/clients/:username/disable

Disable client.

### POST /api/v1/clients/:username/roles

Assign role to client.

Request:

```json
{
  "role_name": "readers",
  "priority": 1
}
```

### DELETE /api/v1/clients/:username/roles/:role_name

Remove role from client.

## Roles

### POST /api/v1/roles

Create role.

Request:

```json
{
  "name": "readers"
}
```

### GET /api/v1/roles

List roles (plain text response).

### GET /api/v1/roles/:role_name

Get role details and ACLs (plain text response).

### DELETE /api/v1/roles/:role_name

Delete role.

### POST /api/v1/roles/:role_name/acls

Add role ACL.

Request:

```json
{
  "topic": "sensors/#",
  "aclType": "subscribePattern",
  "permission": "allow"
}
```

### DELETE /api/v1/roles/:role_name/acls?acl_type=<type>&topic=<topic>

Remove role ACL via query parameters.

## Groups

### POST /api/v1/groups

Create group.

Request:

```json
{
  "name": "operators"
}
```

### GET /api/v1/groups

List groups (plain text response).

### GET /api/v1/groups/:group_name

Get group details (plain text response).

### DELETE /api/v1/groups/:group_name

Delete group.

### POST /api/v1/groups/:group_name/roles

Assign role to group.

Request:

```json
{
  "role_name": "readers",
  "priority": 1
}
```

### DELETE /api/v1/groups/:group_name/roles/:role_name

Remove role from group.

### POST /api/v1/groups/:group_name/clients

Add client to group.

Request:

```json
{
  "username": "clientA",
  "priority": 1
}
```

### DELETE /api/v1/groups/:group_name/clients/:username

Remove client from group.

## Broker Logs

### GET /api/v1/logs/broker?lines=<n>

Returns last N lines from `/var/log/mosquitto/mosquitto.log`.

### GET /api/v1/logs/stream?backfill=<n>

Streams logs with Server-Sent Events (SSE) using `tail -F`.
