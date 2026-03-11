use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct ConfigResponse {
    pub message: String,
    pub status: String,
}

#[derive(Deserialize)]
pub struct ConfigUpdateRequest {
    pub config_content: String,
}

use crate::dynsec::DynSecCoordinator;
use serde_json::json;

pub struct ApiState {
    pub conf_path: String,
    pub dynsec: Arc<DynSecCoordinator>,
}

pub async fn start_api_server(conf_path: String) {
    crate::log_info(&format!("mosqops: Starting Axum server on port 8080, conf_path: {}", conf_path));

    let dynsec_client = match DynSecCoordinator::new().await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            crate::log_error(&format!("mosqops: Fatal error initializing DynSecCoordinator: {}", e));
            return;
        }
    };

    let state = Arc::new(ApiState { 
        conf_path,
        dynsec: dynsec_client 
    });

    let app = Router::new()
        .route("/api/config", get(get_config).post(update_config))
        .route("/api/restart", post(trigger_restart))
        .route("/api/v1/clients", post(create_client).get(list_clients))
        .route("/api/v1/clients/:username", get(get_client).delete(remove_client))
        .route("/api/v1/clients/:username/enable", axum::routing::put(enable_client))
        .route("/api/v1/clients/:username/disable", axum::routing::put(disable_client))
        .route("/api/v1/clients/:username/roles", post(add_client_role))
        .route("/api/v1/clients/:username/roles/:role_name", axum::routing::delete(remove_client_role))
        
        .route("/api/v1/roles", post(create_role).get(list_roles))
        .route("/api/v1/roles/:role_name", get(get_role).delete(delete_role))
        .route("/api/v1/roles/:role_name/acls", post(add_role_acl).delete(remove_role_acl))
        
        .route("/api/v1/groups", post(create_group).get(list_groups))
        .route("/api/v1/groups/:group_name", get(get_group).delete(delete_group))
        .route("/api/v1/groups/:group_name/roles", post(add_group_role))
        .route("/api/v1/groups/:group_name/roles/:role_name", axum::routing::delete(remove_group_role))
        .route("/api/v1/groups/:group_name/clients", post(add_client_to_group))
        .route("/api/v1/groups/:group_name/clients/:username", axum::routing::delete(remove_client_from_group))
        .route("/api/v1/health", get(health_check))
        
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

pub async fn health_check() -> &'static str {
    "OK"
}

async fn get_config(State(state): State<Arc<ApiState>>) -> Result<String, (StatusCode, String)> {
    match std::fs::read_to_string(&state.conf_path) {
        Ok(content) => Ok(content),
        Err(e) => {
            crate::log_error(&format!("mosqops: Failed to read config: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read config file: {}", e),
            ))
        }
    }
}

async fn update_config(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<ConfigUpdateRequest>,
) -> Result<Json<ConfigResponse>, (StatusCode, String)> {
    crate::log_info(&format!("mosqops: Updating config at {}", state.conf_path));
    
    match std::fs::write(&state.conf_path, &payload.config_content) {
        Ok(_) => Ok(Json(ConfigResponse {
            message: "Configuration successfully updated.".into(),
            status: "ok".into(),
        })),
        Err(e) => {
            crate::log_error(&format!("mosqops: Failed to write config: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to write config file: {}", e),
            ))
        }
    }
}

async fn trigger_restart() -> Json<ConfigResponse> {
    crate::log_info("mosqops: Restart requested via API. Terminating process to allow service manager to restart...");
    
    // Spawn a delayed exit so we can return the HTTP 200 OK response first
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });

    Json(ConfigResponse {
        message: "Restart triggered. Broker is terminating.".into(),
        status: "ok".into(),
    })
}

// ----------------------------------------------------------------------------
// Dynamic Security API
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ClientCreate {
    pub username: String,
    pub password: String,
}

#[derive(serde::Serialize)]
pub struct ClientResponse {
    pub username: String,
    pub message: String,
    pub success: bool,
}

pub async fn create_client(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<ClientCreate>,
) -> Result<Json<ClientResponse>, (StatusCode, String)> {
    
    // 1. Create client
    let create_args = json!({
        "username": payload.username,
        "password": payload.password,
    });
    
    match state.dynsec.execute_command("createClient", create_args).await {
        Ok(_) => {
            Ok(Json(ClientResponse {
                username: payload.username,
                message: "Client created and password set successfully".into(),
                success: true,
            }))
        },
        Err(e) => {
            Err((
                StatusCode::BAD_REQUEST,
                format!("Error creating client: {}", e),
            ))
        }
    }
}

pub async fn list_clients(
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("listClients", json!({})).await {
        Ok(response) => {
            if let Some(clients) = response.data.get("clients").and_then(|c| c.as_array()) {
                let usernames: Vec<String> = clients.iter()
                    .filter_map(|c| {
                        if let Some(u) = c.as_str() { Some(u.to_string()) }
                        else { c.get("username").and_then(|u| u.as_str()).map(|s| s.to_string()) }
                    })
                    .collect();
                Ok(format!("Clients:\n{}", usernames.join("\n")))
            } else {
                Ok("Clients:\n".to_string())
            }
        },
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("Failed to list clients: {}", e)))
    }
}

pub async fn get_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("getClient", json!({"username": username})).await {
        Ok(response) => {
            let mut result = format!("Username: {}\n", username);
            if let Some(client_id) = response.data.get("clientid").and_then(|id| id.as_str()) {
                result.push_str(&format!("Clientid: {}\n", client_id));
            }
            if let Some(roles) = response.data.get("roles").and_then(|r| r.as_array()) {
                for role in roles {
                    let role_name = role.get("rolename").and_then(|n| n.as_str()).unwrap_or("");
                    let priority = role.get("priority").and_then(|p| p.as_i64()).unwrap_or(1);
                    result.push_str(&format!("Roles: {} (priority: {})\n", role_name, priority));
                }
            }
            if let Some(groups) = response.data.get("groups").and_then(|g| g.as_array()) {
                let group_names: Vec<String> = groups.iter().filter_map(|g| g.get("groupname").and_then(|n| n.as_str()).map(|s| s.to_string())).collect();
                if !group_names.is_empty() {
                    result.push_str(&format!("Groups: {}\n", group_names.join(", ")));
                }
            }
            Ok(result)
        },
        Err(e) => Err((StatusCode::NOT_FOUND, format!("Client not found: {}", e)))
    }
}

pub async fn enable_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("enableClient", json!({"username": username})).await {
        Ok(_) => Ok(Json(json!({"message": format!("Client {} enabled successfully", username)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("Failed to enable client {}: {}", username, e)))
    }
}

pub async fn disable_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("disableClient", json!({"username": username})).await {
        Ok(_) => Ok(Json(json!({"message": format!("Client {} disabled successfully", username)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("Failed to disable client {}: {}", username, e)))
    }
}

pub async fn remove_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("deleteClient", json!({"username": username})).await {
        Ok(_) => Ok(Json(json!({"message": format!("Client {} removed successfully", username)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("Failed to remove client: {}", e)))
    }
}

#[derive(serde::Deserialize)]
pub struct RoleAssignment {
    pub role_name: String,
    pub priority: Option<i32>,
}

pub async fn add_client_role(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RoleAssignment>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let prio = payload.priority.unwrap_or(1);
    match state.dynsec.execute_command("addClientRole", json!({
        "username": username,
        "rolename": payload.role_name,
        "priority": prio
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("Role {} assigned to client {}", payload.role_name, username)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn remove_client_role(
    axum::extract::Path((username, role_name)): axum::extract::Path<(String, String)>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("removeClientRole", json!({
        "username": username,
        "rolename": role_name,
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("Role {} removed from client {}", role_name, username)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

// ----------------------------------------------------------------------------
// ROLE ENDPOINTS
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct RoleCreate {
    pub name: String,
}

pub async fn create_role(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RoleCreate>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("createRole", json!({"rolename": payload.name})).await {
        Ok(_) => Ok(Json(json!({"message": format!("Role {} created successfully", payload.name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn list_roles(
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("listRoles", json!({})).await {
        Ok(response) => {
            if let Some(roles) = response.data.get("roles").and_then(|r| r.as_array()) {
                let rolenames: Vec<String> = roles.iter()
                    .filter_map(|r| {
                        if let Some(n) = r.as_str() { Some(n.to_string()) }
                        else { r.get("rolename").and_then(|u| u.as_str()).map(|s| s.to_string()) }
                    })
                    .collect();
                Ok(format!("Roles:\n{}", rolenames.join("\n")))
            } else {
                Ok("Roles:\n".to_string())
            }
        },
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn get_role(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("getRole", json!({"rolename": role_name})).await {
        Ok(response) => {
            let mut result = format!("Role: {}\n", role_name);
            if let Some(acls) = response.data.get("acls").and_then(|a| a.as_array()) {
                if !acls.is_empty() {
                    result.push_str("ACLs:\n");
                    for acl in acls {
                        let acl_type = acl.get("acltype").and_then(|t| t.as_str()).unwrap_or("");
                        let allow = acl.get("allow").and_then(|a| a.as_bool()).unwrap_or(true);
                        let perm = if allow { "allow" } else { "deny" };
                        let topic = acl.get("topic").and_then(|t| t.as_str()).unwrap_or("");
                        let priority = acl.get("priority").and_then(|p| p.as_i64()).unwrap_or(0);
                        if priority > 0 {
                            result.push_str(&format!("{}: {}: {} (priority: {})\n", acl_type, perm, topic, priority));
                        } else {
                            result.push_str(&format!("{}: {}: {}\n", acl_type, perm, topic));
                        }
                    }
                }
            }
            Ok(result)
        },
        Err(e) => Err((StatusCode::NOT_FOUND, format!("Role not found: {}", e)))
    }
}

pub async fn delete_role(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("deleteRole", json!({"rolename": role_name})).await {
        Ok(_) => Ok(Json(json!({"message": format!("Role {} deleted successfully", role_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

#[derive(serde::Deserialize)]
pub struct AclRequest {
    pub topic: String,
    #[serde(rename="aclType")]
    pub acl_type: String,
    pub permission: String,
}

pub async fn add_role_acl(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<AclRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let allow = payload.permission.to_lowercase() == "allow";
    match state.dynsec.execute_command("addRoleACL", json!({
        "rolename": role_name,
        "acltype": payload.acl_type,
        "topic": payload.topic,
        "allow": allow
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("ACL added successfully to role {}", role_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

#[derive(serde::Deserialize)]
pub struct RemoveAclQuery {
    pub acl_type: String,
    pub topic: String,
}

pub async fn remove_role_acl(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<RemoveAclQuery>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("removeRoleACL", json!({
        "rolename": role_name,
        "acltype": query.acl_type,
        "topic": query.topic
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("ACL removed from role {} successfully", role_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

// ----------------------------------------------------------------------------
// GROUP ENDPOINTS
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct GroupCreate {
    pub name: String,
}

pub async fn create_group(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<GroupCreate>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("createGroup", json!({"groupname": payload.name})).await {
        Ok(_) => Ok(Json(json!({"message": format!("Group {} created successfully", payload.name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn list_groups(
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("listGroups", json!({})).await {
        Ok(response) => {
            if let Some(groups) = response.data.get("groups").and_then(|g| g.as_array()) {
                let groupnames: Vec<String> = groups.iter()
                    .filter_map(|g| {
                        if let Some(n) = g.as_str() { Some(n.to_string()) }
                        else { g.get("groupname").and_then(|u| u.as_str()).map(|s| s.to_string()) }
                    })
                    .collect();
                Ok(format!("Groups:\n{}", groupnames.join("\n")))
            } else {
                Ok("Groups:\n".to_string())
            }
        },
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn get_group(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("getGroup", json!({"groupname": group_name})).await {
        Ok(response) => {
            let mut result = format!("Group: {}\n", group_name);
            if let Some(roles) = response.data.get("roles").and_then(|r| r.as_array()) {
                for role in roles {
                    let role_name = role.get("rolename").and_then(|n| n.as_str()).unwrap_or("");
                    result.push_str(&format!("Roles: {}\n", role_name));
                }
            }
            if let Some(clients) = response.data.get("clients").and_then(|c| c.as_array()) {
                for client in clients {
                    let client_name = client.get("username").and_then(|n| n.as_str()).unwrap_or("");
                    result.push_str(&format!("Clients: {}\n", client_name));
                }
            }
            Ok(result)
        },
        Err(e) => Err((StatusCode::NOT_FOUND, format!("Group not found: {}", e)))
    }
}

pub async fn delete_group(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("deleteGroup", json!({"groupname": group_name})).await {
        Ok(_) => Ok(Json(json!({"message": format!("Group {} deleted successfully", group_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn add_group_role(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RoleAssignment>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("addGroupRole", json!({
        "groupname": group_name,
        "rolename": payload.role_name
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("Role {} assigned to group {}", payload.role_name, group_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn remove_group_role(
    axum::extract::Path((group_name, role_name)): axum::extract::Path<(String, String)>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("removeGroupRole", json!({
        "groupname": group_name,
        "rolename": role_name
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("Role {} removed from group {}", role_name, group_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

#[derive(serde::Deserialize)]
pub struct GroupClientAdd {
    pub username: String,
    pub priority: Option<i32>,
}

pub async fn add_client_to_group(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<GroupClientAdd>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let prio = payload.priority.unwrap_or(1);
    match state.dynsec.execute_command("addGroupClient", json!({
        "groupname": group_name,
        "username": payload.username,
        "priority": prio
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("Client {} added to group {} successfully", payload.username, group_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}

pub async fn remove_client_from_group(
    axum::extract::Path((group_name, username)): axum::extract::Path<(String, String)>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.dynsec.execute_command("removeGroupClient", json!({
        "groupname": group_name,
        "username": username
    })).await {
        Ok(_) => Ok(Json(json!({"message": format!("Client {} removed from group {} successfully", username, group_name)}))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e))
    }
}
