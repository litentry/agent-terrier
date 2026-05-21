use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{
    error::AppResult,
    state::SharedState,
};

pub async fn shielding_key(
    State(state): State<SharedState>,
) -> AppResult<Json<Value>> {
    let pub_key_bytes = state.shielding_public_key.to_bytes().to_vec();
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pub_key_bytes);
    Ok(Json(json!({ "public_key": encoded })))
}
