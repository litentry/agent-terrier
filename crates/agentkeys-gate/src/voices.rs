//! Voice catalog returned by the explicitly injected speech adapter.
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Voice {
    pub id: String,
    pub name: String,
    pub scenario: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VoicesResponse {
    pub voices: Vec<Voice>,
}
