//! Tool registry — the 7 active + 3 schema-only tools listed in issue #107.
//!
//! Tool naming follows the issue verbatim: dotted `agentkeys.<area>.<verb>`.
//! Each handler returns a `Value` that gets wrapped in the MCP `tools/call`
//! envelope by `server::dispatch_tool_call`.

pub mod audit;
pub mod cap;
pub mod identity;
pub mod memory;
pub mod permission;
pub mod stubs;

use crate::mcp::ToolDescriptor;
use serde_json::json;

pub const TOOL_IDENTITY_WHOAMI: &str = "agentkeys.identity.whoami";
pub const TOOL_MEMORY_GET: &str = "agentkeys.memory.get";
pub const TOOL_MEMORY_PUT: &str = "agentkeys.memory.put";
pub const TOOL_PERMISSION_CHECK: &str = "agentkeys.permission.check";
pub const TOOL_CAP_MINT: &str = "agentkeys.cap.mint";
pub const TOOL_CAP_REVOKE: &str = "agentkeys.cap.revoke";
pub const TOOL_AUDIT_APPEND: &str = "agentkeys.audit.append";
pub const TOOL_DELEGATION_GRANT: &str = "agentkeys.delegation.grant";
pub const TOOL_DELEGATION_REVOKE: &str = "agentkeys.delegation.revoke";
pub const TOOL_APPROVAL_REQUEST: &str = "agentkeys.approval.request";

pub fn all_descriptors() -> Vec<ToolDescriptor> {
    // NOTE on schemas: `actor`, `operator_omni`, `device_key_hash` are
    // ambient identity fields the LLM has no way to fabricate. They're
    // resolved server-side from MCP_DEFAULT_* env vars (auto-set to the
    // demo fixture in --backend=in-memory mode). LLM-callable params
    // (`namespace`, `content`, `scope`, etc.) stay in `required`.
    //
    // NOTE on descriptions: imperatives ("ALWAYS use this when …") +
    // bilingual EN/中 keywords trigger the xiaozhi cloud LLM's tool
    // selection more reliably than soft "use this when". The 3 M4
    // schema-only stubs (delegation.grant/revoke, approval.request) are
    // intentionally NOT advertised here — they stay dispatchable via
    // tools/call but skipping them shrinks the tools/list payload (which
    // has a token budget) and avoids confusing the LLM with not-yet-
    // implemented options.
    vec![
        ToolDescriptor {
            name: TOOL_IDENTITY_WHOAMI.into(),
            description: "Return the current user's identity (account id, display name, permissions). 返回当前用户的身份信息（账号、显示名、权限）。Use when the user asks 'who am I' / '我是谁'.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "actor": {"type": "string", "description": "Optional. Server uses configured default."}
                }
            }),
        },
        ToolDescriptor {
            name: TOOL_MEMORY_GET.into(),
            description: "ALWAYS use this tool to recall what the user previously asked you to remember. \
回忆用户之前保存或告诉你记住的内容。\
EN triggers: 'where did I go', 'where am I going', 'what do I like', 'who is my <family>', 'do I have allergies', 'remember when I…', 'recall my …'. \
中文触发词: '我去过哪里', '我这周末去哪里玩', '我喜欢什么', '我对什么过敏', '我家人', '记得我'. \
Returns the saved note as a plain-text string under `content`.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "Topic of the memory. Pick: 'travel' (trips, destinations, plans / 旅行、行程、计划); 'family' (relatives, birthdays / 家人、生日); 'profile' (preferences, allergies, dietary / 偏好、过敏、饮食). Default to 'travel' when the user asks about places or trips."
                    }
                },
                "required": ["namespace"]
            }),
        },
        ToolDescriptor {
            name: TOOL_MEMORY_PUT.into(),
            description: "ALWAYS use this tool to save a note the user wants you to remember. \
保存用户希望你记住的笔记。\
EN triggers: 'remember that …', 'note that …', 'save this', 'don't forget …'. \
中文触发词: '记住…', '帮我记一下…', '别忘了…'. \
Group by topic via `namespace`.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "Topic: 'travel', 'family', or 'profile'. 主题: 旅行 / 家人 / 偏好."
                    },
                    "content": {"type": "string", "description": "The note in natural language. 笔记内容。"}
                },
                "required": ["namespace", "content"]
            }),
        },
        ToolDescriptor {
            name: TOOL_PERMISSION_CHECK.into(),
            description: "ALWAYS use this tool BEFORE any action that spends money — orders, purchases, payments — to verify the amount is within the user's daily cap. \
在执行任何花钱的操作（下单、购买、支付）之前，必须先用此工具检查金额是否超过每日上限。\
EN triggers: 'buy', 'order', 'pay', 'spend ¥…', 'purchase'. \
中文触发词: '买', '下单', '付', '点 X 块的…', '花…'. \
Returns verdict=accept|deny|ask_parent. On deny, refuse politely and quote the `reason`/`explanation` to the user.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "description": "Action category. For money-spending actions, ALWAYS use 'payment.spend'."
                    },
                    "params": {
                        "type": "object",
                        "description": "For payment.spend, pass {amount_rmb: <integer>} where amount_rmb is the price in RMB the user wants to spend.",
                        "additionalProperties": true
                    }
                },
                "required": ["scope", "params"]
            }),
        },
        ToolDescriptor {
            name: TOOL_CAP_MINT.into(),
            description: "Internal: mint a short-lived capability token. The LLM rarely needs this directly — memory.get/put and permission.check do it internally. Only call explicitly when you need a raw token for a custom flow.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "op": {
                        "type": "string",
                        "enum": ["cred_store", "cred_fetch", "memory_put", "memory_get"]
                    },
                    "params": {
                        "type": "object",
                        "properties": {
                            "service": {"type": "string"}
                        }
                    },
                    "ttl": {"type": "integer", "default": 300}
                },
                "required": ["op"]
            }),
        },
        ToolDescriptor {
            name: TOOL_CAP_REVOKE.into(),
            description: "Revoke a cap by id. M1 records locally; broker endpoint scheduled for M4.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cap_id": {"type": "string"}
                },
                "required": ["cap_id"]
            }),
        },
        ToolDescriptor {
            name: TOOL_AUDIT_APPEND.into(),
            description: "Append an audit envelope. Real-time off-chain feed; 2-min batched on-chain anchor (issue #109).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "actor": {"type": "string"},
                    "event": {
                        "type": "object",
                        "properties": {
                            "operator_omni": {"type": "string"},
                            "op_kind": {"type": "integer"},
                            "op_body": {"type": "object", "additionalProperties": true},
                            "result": {"type": "integer", "enum": [0, 1, 2]},
                            "intent_text": {"type": "string"}
                        },
                        "required": ["operator_omni", "op_kind", "result"]
                    }
                },
                "required": ["actor", "event"]
            }),
        },
        // M4 schema-only stubs (delegation.grant, delegation.revoke,
        // approval.request) intentionally skipped — they're still
        // dispatchable via tools/call and return the per-issue-#107
        // `not_implemented_in_v1` error, but advertising them in
        // tools/list wastes the LLM's tool budget and risks the model
        // calling unimplemented endpoints. Re-add here in M4 when they
        // ship.
    ]
}
