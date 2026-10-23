//! Authenticated, bounded proxy to the separately supervised DPI control plane.
//! This router is nested inside the existing Landscape JWT middleware.
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Query},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const BACKEND: &str = "http://127.0.0.1:6310";
const MAX_RESPONSE: usize = 2 * 1024 * 1024;

pub fn routes<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/status", get(status))
        .route("/catalog", get(catalog))
        .route("/policy", put(save_policy))
        .route("/apply", post(apply))
        .route("/stop", post(stop))
        .layer(DefaultBodyLimit::max(1024 * 1024))
}

fn unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
        "error_id": "dpi.control_unavailable",
        "message": "应用分流控制服务暂不可用，请检查应用分流服务状态。"
    }))).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogQuery {
    #[serde(default)] q: String,
    #[serde(default)] offset: u32,
    #[serde(default = "page_size")] limit: u16,
}
fn page_size() -> u16 { 50 }

async fn status() -> Response {
    forward(reqwest::Method::GET, "/status", None, None).await
}
async fn catalog(Query(query): Query<CatalogQuery>) -> Response {
    if query.q.chars().count() > 128 || query.limit == 0 || query.limit > 100 || query.offset > 100_000 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error_id":"dpi.invalid_query", "message":"查询条件或分页范围无效。"}))).into_response();
    }
    forward(reqwest::Method::GET, "/catalog", Some(vec![
        ("q", query.q), ("offset", query.offset.to_string()), ("limit", query.limit.to_string())
    ]), None).await
}
async fn save_policy(Json(body): Json<Value>) -> Response {
    forward(reqwest::Method::PUT, "/policy", None, Some(body)).await
}
async fn apply(Json(body): Json<Value>) -> Response {
    forward(reqwest::Method::POST, "/apply", None, Some(body)).await
}
async fn stop(Json(body): Json<Value>) -> Response {
    forward(reqwest::Method::POST, "/stop", None, Some(body)).await
}

async fn forward(method: reqwest::Method, path: &'static str,
                 query: Option<Vec<(&str, String)>>, body: Option<Value>) -> Response {
    // Only trusted service configuration can select the credential file. The backend
    // URL and the set of paths above are fixed and never come from a browser input.
    let token_path = std::env::var_os("LANDSCAPE_DPI_TOKEN_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/var/lib/landscape-dpi/control.token".into());
    let Ok(token) = tokio::fs::read_to_string(token_path).await else { return unavailable(); };
    let token = token.trim();
    if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') { return unavailable(); }
    let Ok(client) = reqwest::Client::builder()
        .no_proxy().redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2)).timeout(Duration::from_secs(95)).build()
        else { return unavailable(); };
    let mut request = client.request(method, format!("{BACKEND}{path}")).bearer_auth(token);
    if let Some(query) = query { request = request.query(&query); }
    if let Some(body) = body { request = request.json(&body); }
    let Ok(mut upstream) = request.send().await else { return unavailable(); };
    let status = upstream.status();
    if ![200, 400, 409, 413, 422, 503].contains(&status.as_u16()) { return unavailable(); }
    let mut payload = Vec::new();
    loop {
        match upstream.chunk().await {
            Ok(Some(chunk)) if payload.len() + chunk.len() <= MAX_RESPONSE => payload.extend_from_slice(&chunk),
            Ok(None) => break,
            _ => return unavailable(),
        }
    }
    if serde_json::from_slice::<Value>(&payload).is_err() { return unavailable(); }
    Response::builder().status(status.as_u16())
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(payload)).unwrap_or_else(|_| unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_schema_rejects_unknown_fields() {
        assert!(serde_json::from_value::<CatalogQuery>(json!({"q":"Steam","url":"http://example.invalid"})).is_err());
        let q=serde_json::from_value::<CatalogQuery>(json!({})).unwrap();
        assert_eq!(q.limit,50); assert_eq!(q.offset,0);
    }
    #[tokio::test]
    async fn invalid_query_cannot_contact_controller() {
        for query in [CatalogQuery{q:"x".repeat(129),offset:0,limit:50},CatalogQuery{q:String::new(),offset:0,limit:101},CatalogQuery{q:String::new(),offset:100001,limit:1}] {
            assert_eq!(catalog(Query(query)).await.status(),StatusCode::BAD_REQUEST);
        }
    }
}
