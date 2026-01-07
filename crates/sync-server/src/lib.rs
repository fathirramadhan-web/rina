//! Optional self-hostable sync server for Vera/RINA.
//!
//! Deploy with Docker: run this binary in a container with `DATABASE_URL`
//! pointing at a PostgreSQL service and `JWT_SECRET` set from a secret store;
//! expose `BIND_ADDR` (default `0.0.0.0:8080`) behind TLS.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use jsonwebtoken::{decode, encode, Algorithm as JwtAlg, DecodingKey, EncodingKey, Header, Validation};
use rina_core::crypto::KdfParams;
use rina_sync::protocol::{self, MergeDecision, PullResponse, PushItem, SyncRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Json as SqlJson;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

const ACCESS_TTL: u64 = 15 * 60;
const REFRESH_TTL: u64 = 30 * 24 * 60 * 60;

/// Server config. All values come from the environment.
#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub jwt_secret: String,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| AppError::config("DATABASE_URL is required"))?;
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| AppError::config("JWT_SECRET is required"))?;
        if jwt_secret.len() < 32 {
            return Err(AppError::config("JWT_SECRET must be at least 32 bytes"));
        }
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
        Ok(Self { database_url, bind_addr, jwt_secret })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub cfg: Arc<Config>,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Config(String),
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error")]
    Internal(String),
}

impl AppError {
    fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    code: &'static str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message): (StatusCode, &'static str, &'static str) = match &self {
            Self::Config(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "internal server error")
            }
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", "invalid request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict", "conflict"),
        };
        if status.is_server_error() {
            tracing::error!(error = %self, code);
        }
        (status, Json(ErrorBody { error: message, code })).into_response()
    }
}

type ApiResult<T> = Result<T, AppError>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    did: String,
    #[serde(rename = "typ")]
    kind: String,
    exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshClaims {
    sub: String,
    did: String,
    jti: String,
    exp: u64,
}

/// Argon2id PHC hash of an HKDF-derived client secret.
fn hash_secret(secret: &str) -> ApiResult<String> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT);
    let salt = SaltString::generate(&mut OsRng);
    argon
        .hash_password(secret.as_bytes(), &salt)
        .map(|p| p.to_string())
        .map_err(|e| AppError::Internal(format!("argon2: {e}")))
}

fn verify_secret(phc: &str, secret: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else { return false };
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok()
}

fn hash_refresh(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    B64.encode(h.finalize())
}

fn sign_access(cfg: &Config, user_id: Uuid, device_id: Uuid) -> ApiResult<String> {
    encode(
        &Header::new(JwtAlg::HS256),
        &Claims {
            sub: user_id.to_string(),
            did: device_id.to_string(),
            kind: "access".to_string(),
            exp: now_secs() + ACCESS_TTL,
        },
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("jwt: {e}")))
}

fn sign_refresh(cfg: &Config, user_id: Uuid, device_id: Uuid, jti: Uuid) -> ApiResult<String> {
    encode(
        &Header::new(JwtAlg::HS256),
        &RefreshClaims {
            sub: user_id.to_string(),
            did: device_id.to_string(),
            jti: jti.to_string(),
            exp: now_secs() + REFRESH_TTL,
        },
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("jwt: {e}")))
}

fn decode_access(cfg: &Config, token: &str) -> ApiResult<Claims> {
    let mut v = Validation::new(JwtAlg::HS256);
    v.set_required_spec_claims(&["exp", "sub"]);
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &v,
    )
    .map_err(|_| AppError::Unauthorized)?;
    if data.claims.kind != "access" {
        return Err(AppError::Unauthorized);
    }
    Ok(data.claims)
}

fn decode_refresh(cfg: &Config, token: &str) -> ApiResult<RefreshClaims> {
    decode::<RefreshClaims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &Validation::new(JwtAlg::HS256),
    )
    .map(|d| d.claims)
    .map_err(|_| AppError::Unauthorized)
}

/// Issue a fresh token pair; store only the hashed refresh token on the device.
async fn issue_tokens(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
) -> ApiResult<protocol::TokenResponse> {
    let access = sign_access(&state.cfg, user_id, device_id)?;
    let refresh = sign_refresh(&state.cfg, user_id, device_id, Uuid::new_v4())?;
    sqlx::query(
        "UPDATE devices SET refresh_hash = $1, revoked = false WHERE id = $2 AND user_id = $3",
    )
    .bind(hash_refresh(&refresh))
    .bind(device_id)
    .bind(user_id)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(protocol::TokenResponse {
        access_token: access,
        refresh_token: refresh,
        device_id: device_id.to_string(),
    })
}

fn validate_email(email: &str) -> ApiResult<()> {
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if parts.next().is_some()
        || local.is_empty()
        || local.len() > 64
        || domain.len() < 3
        || !domain.contains('.')
        || email.len() > 254
        || email.chars().any(char::is_whitespace)
    {
        return Err(AppError::BadRequest("invalid email".into()));
    }
    Ok(())
}

fn validate_auth_hash(auth_hash: &str) -> ApiResult<()> {
    // Client sends base64 of a 32-byte HKDF subkey, never a raw password.
    if auth_hash.len() < 32 || auth_hash.len() > 256 {
        return Err(AppError::BadRequest("invalid auth_hash".into()));
    }
    let bytes = B64.decode(auth_hash)
        .map_err(|_| AppError::BadRequest("invalid auth_hash".into()))?;
    if bytes.len() != 32 {
        return Err(AppError::BadRequest("invalid auth_hash".into()));
    }
    Ok(())
}

fn validate_registration(req: &protocol::RegisterRequest) -> ApiResult<()> {
    validate_email(&req.email)?;
    validate_auth_hash(&req.auth_hash)?;
    if !(8..=64).contains(&req.kdf_salt.len())
        || req.wrapped_dek.is_empty()
        || req.wrapped_dek.len() > 4096
        || req.wrapped_dek_recovery
            .as_ref()
            .is_some_and(|w| w.is_empty() || w.len() > 4096)
    {
        return Err(AppError::BadRequest("invalid vault metadata".into()));
    }
    if req.kdf.m_cost_kib < 1024 || req.kdf.t_cost == 0 || req.kdf.p_cost == 0 {
        return Err(AppError::BadRequest("invalid kdf params".into()));
    }
    Ok(())
}

/// Bearer-token identity extracted from the `Authorization` header.
#[derive(Debug, Clone, Copy)]
struct Auth {
    user_id: Uuid,
    device_id: Uuid,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?;
        let claims = decode_access(&state.cfg, token)?;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
        let device_id = Uuid::parse_str(&claims.did).map_err(|_| AppError::Unauthorized)?;
        let valid: Option<bool> = sqlx::query_scalar(
            "SELECT revoked FROM devices WHERE id = $1 AND user_id = $2",
        )
        .bind(device_id)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        if valid.unwrap_or(true) {
            return Err(AppError::Unauthorized);
        }
        Ok(Self { user_id, device_id })
    }
}

#[derive(Debug, Deserialize)]
struct PasswordUpdate {
    auth_hash: String,
    kdf_salt: Vec<u8>,
    kdf: KdfParams,
    wrapped_dek: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct RecoveryRequest {
    email: String,
    recovery_auth: String,
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct PullQuery {
    cursor: Option<i64>,
}

#[derive(Debug, Serialize)]
struct AppliedItem {
    id: String,
    seq: i64,
}

#[derive(Debug, Serialize)]
struct DeviceInfo {
    id: String,
    created_at: i64,
    revoked: bool,
}

/// Server-side LWW: does the incoming push replace the stored version?
/// Delegates to `rina_sync::protocol::decide`, the canonical LWW policy.
fn lww_wins(stored_updated_at: i64, incoming: &PushItem) -> bool {
    let remote = SyncRecord {
        id: incoming.id.clone(),
        kind: incoming.kind.clone(),
        blob: incoming.blob.clone(),
        updated_at: incoming.updated_at,
        deleted: incoming.deleted,
        seq: 0,
    };
    matches!(
        protocol::decide(stored_updated_at, &remote),
        MergeDecision::TakeRemote
    )
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/account/register", post(register))
        .route("/account/login", post(login))
        .route("/account/refresh", post(refresh))
        .route("/account/password", post(update_password))
        .route("/account/recovery", post(recover))
        .route("/sync/pull", get(pull))
        .route("/sync/push", post(push))
        .route("/devices", get(list_devices))
        .route("/devices/{id}", delete(revoke_device));
    Router::new().nest("/api/v1", api).with_state(state)
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<protocol::RegisterRequest>,
) -> ApiResult<Json<protocol::TokenResponse>> {
    validate_registration(&req)?;
    let phc = hash_secret(&req.auth_hash)?;
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let kdf_json = serde_json::to_value(req.kdf)
        .map_err(|e| AppError::Internal(format!("kdf json: {e}")))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, email, auth_hash, recovery_hash, kdf_salt, kdf, wrapped_dek, wrapped_dek_recovery) \
         VALUES ($1, $2, $3, NULL, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(&req.email)
    .bind(&phc)
    .bind(&req.kdf_salt)
    .bind(SqlJson(kdf_json))
    .bind(&req.wrapped_dek)
    .bind(req.wrapped_dek_recovery.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    if inserted.rows_affected() == 0 {
        return Err(AppError::Conflict("email already registered".into()));
    }
    sqlx::query("INSERT INTO devices (id, user_id, created_at) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(user_id)
        .bind(now_secs() as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(issue_tokens(&state, user_id, device_id).await?))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<protocol::LoginRequest>,
) -> ApiResult<Json<protocol::TokenResponse>> {
    validate_email(&req.email)?;
    validate_auth_hash(&req.auth_hash)?;
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, auth_hash FROM users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let Some((user_id, phc)) = row else {
        return Err(AppError::Unauthorized);
    };
    if !verify_secret(&phc, &req.auth_hash) {
        return Err(AppError::Unauthorized);
    }
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO devices (id, user_id, created_at) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(user_id)
        .bind(now_secs() as i64)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(issue_tokens(&state, user_id, device_id).await?))
}

async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<Json<protocol::TokenResponse>> {
    let claims = decode_refresh(&state.cfg, &req.refresh_token)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let device_id = Uuid::parse_str(&claims.did).map_err(|_| AppError::Unauthorized)?;
    let stored: Option<(String, bool)> = sqlx::query_as(
        "SELECT refresh_hash, revoked FROM devices WHERE id = $1 AND user_id = $2",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    match stored {
        Some((hash, false)) if hash == hash_refresh(&req.refresh_token) => {}
        _ => return Err(AppError::Unauthorized),
    }
    Ok(Json(issue_tokens(&state, user_id, device_id).await?))
}

/// Rotate the DEK wrap and login secret; sign out every other device.
async fn update_password(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<PasswordUpdate>,
) -> ApiResult<StatusCode> {
    validate_auth_hash(&req.auth_hash)?;
    if !(8..=64).contains(&req.kdf_salt.len())
        || req.wrapped_dek.is_empty()
        || req.wrapped_dek.len() > 4096
    {
        return Err(AppError::BadRequest("invalid vault metadata".into()));
    }
    let phc = hash_secret(&req.auth_hash)?;
    let kdf_json = serde_json::to_value(req.kdf)
        .map_err(|e| AppError::Internal(format!("kdf json: {e}")))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    sqlx::query(
        "UPDATE users SET auth_hash = $1, kdf_salt = $2, kdf = $3, wrapped_dek = $4 WHERE id = $5",
    )
    .bind(&phc)
    .bind(&req.kdf_salt)
    .bind(SqlJson(kdf_json))
    .bind(&req.wrapped_dek)
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    sqlx::query(
        "UPDATE devices SET refresh_hash = '', revoked = true WHERE user_id = $1 AND id <> $2",
    )
    .bind(auth.user_id)
    .bind(auth.device_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Verify the recovery auth secret and return a login token.
async fn recover(
    State(state): State<AppState>,
    Json(req): Json<RecoveryRequest>,
) -> ApiResult<Json<protocol::TokenResponse>> {
    validate_email(&req.email)?;
    validate_auth_hash(&req.recovery_auth)?;
    let row: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, recovery_hash FROM users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let Some((user_id, Some(recovery_phc))) = row else {
        return Err(AppError::Unauthorized);
    };
    if !verify_secret(&recovery_phc, &req.recovery_auth) {
        return Err(AppError::Unauthorized);
    }
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO devices (id, user_id, created_at) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(user_id)
        .bind(now_secs() as i64)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(issue_tokens(&state, user_id, device_id).await?))
}

async fn pull(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<PullQuery>,
) -> ApiResult<Json<PullResponse>> {
    let cursor = q.cursor.unwrap_or(-1);
    let rows: Vec<(String, String, Vec<u8>, i64, bool, i64)> = sqlx::query_as(
        "SELECT id, kind, blob, updated_at, deleted, seq FROM records \
         WHERE user_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT 500",
    )
    .bind(auth.user_id)
    .bind(cursor)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let records: Vec<SyncRecord> = rows
        .into_iter()
        .map(|(id, kind, blob, updated_at, deleted, seq)| SyncRecord {
            id,
            kind,
            blob,
            updated_at,
            deleted,
            seq: seq as u64,
        })
        .collect();
    let new_cursor = records
        .last()
        .map(|r| r.seq as i64)
        .unwrap_or(cursor);
    Ok(Json(PullResponse {
        records,
        cursor: new_cursor as u64,
    }))
}

/// Apply pushes with LWW by `updated_at`; return applied seq per record.
async fn push(
    State(state): State<AppState>,
    auth: Auth,
    Json(items): Json<Vec<PushItem>>,
) -> ApiResult<Json<Vec<AppliedItem>>> {
    if items.is_empty() || items.len() > 1000 {
        return Err(AppError::BadRequest("too many or no push items".into()));
    }
    let mut applied = Vec::with_capacity(items.len());
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    for item in items {
        if item.id.is_empty() || item.id.len() > 512 || item.blob.len() > 1024 * 1024 {
            return Err(AppError::BadRequest("invalid push item".into()));
        }
        let existing: Option<i64> = sqlx::query_scalar(
            "SELECT updated_at FROM records WHERE user_id = $1 AND id = $2",
        )
        .bind(auth.user_id)
        .bind(&item.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(stored_at) = existing {
            if !lww_wins(stored_at, &item) {
                let seq: i64 = sqlx::query_scalar(
                    "SELECT seq FROM records WHERE user_id = $1 AND id = $2",
                )
                .bind(auth.user_id)
                .bind(&item.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
                applied.push(AppliedItem { id: item.id, seq });
                continue;
            }
            let seq: i64 = sqlx::query_scalar(
                "UPDATE records SET kind = $1, blob = $2, updated_at = $3, deleted = $4 \
                 WHERE user_id = $5 AND id = $6 RETURNING seq",
            )
            .bind(&item.kind)
            .bind(&item.blob)
            .bind(item.updated_at)
            .bind(item.deleted)
            .bind(auth.user_id)
            .bind(&item.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
            applied.push(AppliedItem { id: item.id, seq });
        } else {
            let seq: i64 = sqlx::query_scalar(
                "INSERT INTO records (id, user_id, kind, blob, updated_at, deleted) \
                 VALUES ($1, $2, $3, $4, $5, $6) RETURNING seq",
            )
            .bind(&item.id)
            .bind(auth.user_id)
            .bind(&item.kind)
            .bind(&item.blob)
            .bind(item.updated_at)
            .bind(item.deleted)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
            applied.push(AppliedItem { id: item.id, seq });
        }
    }
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(applied))
}

async fn list_devices(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<DeviceInfo>>> {
    let rows: Vec<(Uuid, i64, bool)> = sqlx::query_as(
        "SELECT id, created_at, revoked FROM devices WHERE user_id = $1 ORDER BY created_at ASC",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, created_at, revoked)| DeviceInfo {
                id: id.to_string(),
                created_at,
                revoked,
            })
            .collect(),
    ))
}

async fn revoke_device(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let device_id =
        Uuid::parse_str(&id).map_err(|_| AppError::BadRequest("invalid device id".into()))?;
    if device_id == auth.device_id {
        return Err(AppError::BadRequest("cannot revoke the current device".into()));
    }
    let result = sqlx::query(
        "UPDATE devices SET revoked = true, refresh_hash = '' WHERE id = $1 AND user_id = $2",
    )
    .bind(device_id)
    .bind(auth.user_id)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Create tables on startup. No migrations, no compile-time DB dependency.
pub async fn init_db(database_url: &str) -> ApiResult<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(|e| AppError::Internal(format!("database: {e}")))?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            auth_hash TEXT NOT NULL,
            recovery_hash TEXT,
            kdf_salt BYTEA NOT NULL,
            kdf JSONB NOT NULL,
            wrapped_dek BYTEA NOT NULL,
            wrapped_dek_recovery BYTEA,
            created_at BIGINT NOT NULL
        ); \
         CREATE TABLE IF NOT EXISTS records (
            id TEXT NOT NULL,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            blob BYTEA NOT NULL,
            updated_at BIGINT NOT NULL,
            deleted BOOLEAN NOT NULL,
            seq BIGSERIAL NOT NULL,
            PRIMARY KEY (user_id, id)
        ); \
         CREATE TABLE IF NOT EXISTS devices (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            refresh_hash TEXT NOT NULL DEFAULT '',
            created_at BIGINT NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT false
        )",
    )
    .execute(&pool)
    .await
    .map_err(|e| AppError::Internal(format!("schema: {e}")))?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lww_apply_logic() {
        let incoming = PushItem {
            id: "a".into(),
            kind: "host".into(),
            blob: vec![1],
            updated_at: 10,
            deleted: false,
        };
        assert!(lww_wins(5, &incoming));
        assert!(!lww_wins(10, &incoming));
        assert!(!lww_wins(11, &incoming));
    }

    #[test]
    fn jwt_issue_and_verify_roundtrip() {
        let cfg = Config {
            database_url: "postgres://unused".into(),
            bind_addr: "127.0.0.1:0".into(),
            jwt_secret: "x".repeat(32),
        };
        let user = Uuid::new_v4();
        let device = Uuid::new_v4();
        let access = sign_access(&cfg, user, device).unwrap();
        let claims = decode_access(&cfg, &access).unwrap();
        assert_eq!(claims.sub, user.to_string());
        assert_eq!(claims.did, device.to_string());
        let jti = Uuid::new_v4();
        let refresh = sign_refresh(&cfg, user, device, jti).unwrap();
        assert_eq!(decode_refresh(&cfg, &refresh).unwrap().jti, jti.to_string());
        let other = Config {
            jwt_secret: "y".repeat(32),
            ..cfg.clone()
        };
        assert!(decode_access(&other, &access).is_err());
        assert!(decode_refresh(&other, &refresh).is_err());
    }

    #[test]
    fn request_validation() {
        assert!(validate_registration(&protocol::RegisterRequest {
            email: "a@b.co".into(),
            auth_hash: B64.encode([7u8; 32]),
            kdf_salt: vec![0u8; 16],
            kdf: KdfParams::insecure_for_tests(),
            wrapped_dek: vec![1u8; 40],
            wrapped_dek_recovery: None,
        })
        .is_ok());
        assert!(validate_email("bad").is_err());
        assert!(validate_email("a@b.co").is_ok());
        assert!(validate_auth_hash("short").is_err());
        assert!(validate_auth_hash(&B64.encode([7u8; 32])).is_ok());
    }

    #[test]
    fn argon2_phc_roundtrip() {
        let secret = B64.encode([9u8; 32]);
        let phc = hash_secret(&secret).unwrap();
        assert!(verify_secret(&phc, &secret));
        assert!(!verify_secret(&phc, &B64.encode([8u8; 32])));
    }

    #[test]
    fn error_shape() {
        let resp = AppError::BadRequest("bad".into()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL pointing at a running PostgreSQL instance"]
    async fn db_integration() {
        let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL");
        let pool = init_db(&url).await.expect("database");
        assert!(!pool.is_closed());
    }
}
