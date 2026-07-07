//! `agentkeys wire <runtime>` — provision a Task Host with AgentKeys
//! IAM-guarantee hooks.
//!
//! Idempotent per AGENTS.md "Idempotent remote-setup rule": every step
//! pre-checks state, writes only on drift, and logs one of
//! `ok proceeding / skip <reason> / fail <reason>`. Re-runs are no-ops.
//! `--check-only` reports drift without writing (the nightly drift check).
//!
//! Phase 1.a ships the Hermes adapter. The `RuntimeAdapter` trait is the
//! seam additional runtimes (Claude Code, Codex, OpenClaw) slot into in
//! Phase 1.b — see docs/plan/phase-1-fresh-user-wire-onboarding.md §4.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

/// Sentinel markers delimiting the AgentKeys-managed region of a runtime
/// config file. Everything between them is owned by `agentkeys wire`;
/// everything outside is the operator's and is never touched.
const BLOCK_START: &str =
    "# >>> agentkeys wire (managed block — do not edit; re-run `agentkeys wire`) >>>";
const BLOCK_END: &str = "# <<< agentkeys wire <<<";

#[derive(Debug, Clone)]
pub struct WireRequest {
    pub actor: String,
    pub operator: String,
    /// Comma-separated memory namespaces the pre_llm_call hook injects.
    pub namespaces: String,
    /// Scope the pre_tool_call permission gate checks (default payment.spend).
    pub payment_scope: String,
    pub mcp_url: String,
    pub vendor_token: String,
    /// Operator/agent session JWT baked into the hook scripts as
    /// `AGENTKEYS_SESSION_BEARER` (the hook forwards it to the MCP server →
    /// broker cap-mint). Empty for the in-memory backend. Note: JWTs expire
    /// (TTL ≤ 5h) — re-run `agentkeys wire` to refresh, or point the demo at
    /// a fresh session.
    pub session_bearer: String,
    /// Memory engine baked into the pre_llm_call hook (`passthrough` | `lexical`,
    /// plan §6a). `passthrough`/empty injects the whole namespace and emits no
    /// engine env, so the generated script stays byte-identical to the default.
    pub memory_engine: String,
    /// Optional cap on how many memory lines the engine injects (None = all).
    pub memory_max_lines: Option<u32>,
    /// OpenViking server URL baked as `OPENVIKING_ENDPOINT` into the hook when
    /// `memory_engine == "openviking"` (plan §6a). None → not emitted.
    pub memory_engine_endpoint: Option<String>,
    /// Optional OpenViking API key baked as `OPENVIKING_API_KEY`.
    pub memory_engine_api_key: Option<String>,
    /// When true, report drift without writing (drift-check / dry-run).
    pub check_only: bool,
}

/// Per-step outcome, rendered to the operator with the AGENTS.md convention.
enum Outcome {
    Ok(String),
    Skip(String),
    Fail(String),
}

impl Outcome {
    fn render(&self, step: &str) -> String {
        match self {
            Outcome::Ok(m) => format!("  step {step}: ok proceeding ({m})"),
            Outcome::Skip(m) => format!("  step {step}: skip {m}"),
            Outcome::Fail(m) => format!("  step {step}: fail {m}"),
        }
    }
    fn is_fail(&self) -> bool {
        matches!(self, Outcome::Fail(_))
    }
}

/// Absolute path to the running `agentkeys` binary, so the generated hook
/// scripts call the same binary regardless of the runtime subprocess's PATH.
fn agentkeys_bin() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "agentkeys".to_string())
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME not set")
}

// ─── RuntimeAdapter seam ────────────────────────────────────────────────

trait RuntimeAdapter {
    fn name(&self) -> &'static str;
    /// Return the installed runtime version, or None if not installed.
    fn detect(&self) -> Option<String>;
    /// Apply (or, when check_only, diff) the wiring. Returns per-step log.
    fn apply(&self, bin: &str, req: &WireRequest) -> Result<Vec<(String, Outcome)>>;
    /// Verify via the runtime's own hook-health command. Best-effort.
    fn verify(&self) -> Outcome;
}

// ─── Hermes adapter ─────────────────────────────────────────────────────

#[derive(Default)]
struct HermesAdapter {
    /// Root used in place of `$HOME` when building `~/.hermes` paths.
    /// `None` ⇒ the real `$HOME`. Tests inject a fixed root here instead
    /// of `set_var("HOME", ..)` — process env is global, so mutating it
    /// poisons every other test sharing the process.
    home_root: Option<PathBuf>,
}

impl HermesAdapter {
    fn home(&self) -> Result<PathBuf> {
        let root = match &self.home_root {
            Some(root) => root.clone(),
            None => home_dir()?,
        };
        Ok(root.join(".hermes"))
    }
    fn hooks_dir(&self) -> Result<PathBuf> {
        Ok(self.home()?.join("agent-hooks"))
    }
    fn config_path(&self) -> Result<PathBuf> {
        Ok(self.home()?.join("config.yaml"))
    }

    /// The three hook scripts, as (filename, body) pairs.
    fn scripts(&self, bin: &str, req: &WireRequest) -> Vec<(String, String)> {
        let header = |body: &str| -> String {
            format!(
                "#!/usr/bin/env bash\n\
                 # Generated by `agentkeys wire hermes`. Do not edit — re-run wire to update.\n\
                 export AGENTKEYS_ACTOR_OMNI={actor}\n\
                 export AGENTKEYS_OPERATOR_OMNI={operator}\n\
                 export AGENTKEYS_MCP_URL={mcp_url}\n\
                 export AGENTKEYS_MCP_VENDOR_TOKEN={vendor_token}\n\
                 export AGENTKEYS_SESSION_BEARER={session_bearer}\n\
                 {body}\n",
                actor = shell_quote(&req.actor),
                operator = shell_quote(&req.operator),
                mcp_url = shell_quote(&req.mcp_url),
                vendor_token = shell_quote(&req.vendor_token),
                session_bearer = shell_quote(&req.session_bearer),
                body = body,
            )
        };
        let memory_engine_exports = {
            let mut exports = String::new();
            if !req.memory_engine.is_empty() && req.memory_engine != "passthrough" {
                exports.push_str(&format!(
                    "export AGENTKEYS_MEMORY_ENGINE={}\n",
                    shell_quote(&req.memory_engine)
                ));
            }
            if let Some(max_lines) = req.memory_max_lines {
                exports.push_str(&format!("export AGENTKEYS_MEMORY_MAX_LINES={max_lines}\n"));
            }
            if req.memory_engine.eq_ignore_ascii_case("openviking") {
                // Default the endpoint to the local server (the hermes-sandbox image
                // runs openviking-server on :1933 via supervisord) so `openviking`
                // works out of the box; an explicit endpoint (remote / VE-managed)
                // overrides. Without OPENVIKING_ENDPOINT the client is None and the
                // hook silently falls back to lexical — so the default MUST be baked.
                let endpoint = req
                    .memory_engine_endpoint
                    .as_deref()
                    .unwrap_or(agentkeys_memory_openviking::DEFAULT_ENDPOINT);
                exports.push_str(&format!(
                    "export OPENVIKING_ENDPOINT={}\n",
                    shell_quote(endpoint)
                ));
                if let Some(api_key) = req.memory_engine_api_key.as_deref() {
                    exports.push_str(&format!(
                        "export OPENVIKING_API_KEY={}\n",
                        shell_quote(api_key)
                    ));
                }
            }
            exports
        };
        vec![
            (
                "agentkeys-pretool-permission-gate.sh".to_string(),
                header(&format!(
                    "exec {bin} hook check --scope {scope}",
                    scope = shell_quote(&req.payment_scope),
                )),
            ),
            (
                "agentkeys-posttool-audit.sh".to_string(),
                header(&format!("exec {bin} hook audit")),
            ),
            (
                "agentkeys-prellm-memory-inject.sh".to_string(),
                header(&format!(
                    "{memory_engine_exports}exec {bin} hook memory-inject --namespaces {ns}",
                    ns = shell_quote(&req.namespaces),
                )),
            ),
        ]
    }

    /// The managed `hooks:` block referencing the script paths. The
    /// request fields (actor, namespaces, scope) are baked into the
    /// scripts, not the block, so `_req` is currently unused — kept in the
    /// signature as the seam for per-request block content later.
    fn managed_block(&self, _req: &WireRequest) -> Result<String> {
        let dir = self.hooks_dir()?;
        let p = |name: &str| dir.join(name).to_string_lossy().to_string();
        Ok(format!(
            "{BLOCK_START}\n\
             hooks:\n\
             \x20 pre_tool_call:\n\
             \x20   - matcher: \"(?i)(pay|order|purchase|spend|checkout)\"\n\
             \x20     command: \"{pretool}\"\n\
             \x20     timeout: 5\n\
             \x20 post_tool_call:\n\
             \x20   - matcher: \".*\"\n\
             \x20     command: \"{posttool}\"\n\
             \x20     timeout: 5\n\
             \x20 pre_llm_call:\n\
             \x20   - command: \"{prellm}\"\n\
             \x20     timeout: 5\n\
             hooks_auto_accept: true\n\
             {BLOCK_END}",
            pretool = p("agentkeys-pretool-permission-gate.sh"),
            posttool = p("agentkeys-posttool-audit.sh"),
            prellm = p("agentkeys-prellm-memory-inject.sh"),
        ))
    }
}

impl RuntimeAdapter for HermesAdapter {
    fn name(&self) -> &'static str {
        "hermes"
    }

    fn detect(&self) -> Option<String> {
        let out = Command::new("hermes").arg("--version").output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn apply(&self, bin: &str, req: &WireRequest) -> Result<Vec<(String, Outcome)>> {
        let mut log = Vec::new();
        let hooks_dir = self.hooks_dir()?;

        // Step: ensure hooks dir.
        if req.check_only {
            log.push((
                "1 hooks-dir".into(),
                if hooks_dir.exists() {
                    Outcome::Skip(format!("{} exists", hooks_dir.display()))
                } else {
                    Outcome::Ok(format!("[check-only] would create {}", hooks_dir.display()))
                },
            ));
        } else {
            std::fs::create_dir_all(&hooks_dir)
                .with_context(|| format!("create {}", hooks_dir.display()))?;
            // 0o700 — the dir holds bearer-bearing hook scripts; no group/other
            // traversal or read (defense-in-depth with the 0o700 scripts).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&hooks_dir)?.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(&hooks_dir, perms);
            }
            log.push((
                "1 hooks-dir".into(),
                Outcome::Ok(format!("{} ready (0700)", hooks_dir.display())),
            ));
        }

        // Step: write the three hook scripts (idempotent, executable).
        for (i, (name, body)) in self.scripts(bin, req).into_iter().enumerate() {
            let path = hooks_dir.join(&name);
            let outcome = write_if_changed(&path, &body, req.check_only, /*exec=*/ true)?;
            log.push((format!("2.{} script {name}", i + 1), outcome));
        }

        // Step: merge the managed hooks: block into config.yaml.
        let cfg = self.config_path()?;
        let block = self.managed_block(req)?;
        log.push((
            "3 config-block".into(),
            merge_block(&cfg, &block, req.check_only)?,
        ));

        // Step: consent pre-approval is encoded as `hooks_auto_accept: true`
        // inside the managed block (one of Hermes's three escape hatches),
        // so it's covered by step 3. Record it explicitly for the operator.
        log.push((
            "4 consent".into(),
            Outcome::Ok("hooks_auto_accept: true set in managed block".into()),
        ));

        Ok(log)
    }

    fn verify(&self) -> Outcome {
        match Command::new("hermes").args(["hooks", "doctor"]).output() {
            Ok(out) if out.status.success() => Outcome::Ok("hermes hooks doctor passed".into()),
            Ok(out) => Outcome::Fail(format!(
                "hermes hooks doctor exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => Outcome::Skip(format!("hermes hooks doctor not runnable: {e}")),
        }
    }
}

// ─── shared file ops ────────────────────────────────────────────────────

/// Minimal shell single-quote for baking values into generated scripts.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Write `content` to `path` only if it differs from what's there.
/// Returns ok/skip/[check-only] accordingly. Sets the exec bit on Unix
/// when `exec` is true.
fn write_if_changed(
    path: &std::path::Path,
    content: &str,
    check_only: bool,
    exec: bool,
) -> Result<Outcome> {
    let current = std::fs::read_to_string(path).ok();
    if current.as_deref() == Some(content) {
        return Ok(Outcome::Skip(format!("{} matches", path.display())));
    }
    if check_only {
        return Ok(Outcome::Ok(format!(
            "[check-only] would {} {}",
            if current.is_some() { "update" } else { "write" },
            path.display()
        )));
    }
    std::fs::write(path, content).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    if exec {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        // 0o700 (owner rwx only) — these hook scripts export the operator
        // session bearer + vendor token; they only need to be exec'd by the
        // agent's own user (Hermes runs as that user), never read by
        // group/other. Closes the cross-user token-theft vector. (Same-user
        // exposure is architectural — out-of-process custody is issue #144.)
        perms.set_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    let _ = exec; // silence unused on non-unix
    Ok(Outcome::Ok(format!(
        "{} {}",
        if current.is_some() {
            "updated"
        } else {
            "wrote"
        },
        path.display()
    )))
}

/// Strip a column-0 `hooks:` block (and any top-level `hooks_auto_accept:`) from
/// `existing`, returning the remaining text — or `None` if there is no top-level
/// `hooks:` key.
///
/// `agentkeys wire` OWNS the runtime's `hooks:` key: the IAM guarantee depends on
/// the hooks being un-bypassable, and a YAML config allows only one `hooks:` key.
/// So on (re)wire we REPLACE whatever is there — whether it's our own block whose
/// sentinel comments a host re-serialization (`hermes config set`) dropped, or a
/// hand-authored block. This take-over is documented for users in
/// `docs/user-manual.md`.
fn strip_top_level_hooks(existing: &str) -> Option<String> {
    let lines: Vec<&str> = existing.lines().collect();
    let hooks_start = lines
        .iter()
        .position(|l| l.starts_with("hooks:") && *l == l.trim_start())?;
    // The block runs until the next column-0 (non-indented, non-blank) line.
    let mut hooks_end = lines.len();
    for (offset, l) in lines.iter().enumerate().skip(hooks_start + 1) {
        if l.is_empty() {
            continue;
        }
        if !(l.starts_with(' ') || l.starts_with('\t')) {
            hooks_end = offset;
            break;
        }
    }
    // Drop the hooks block + any top-level `hooks_auto_accept:` (our block re-adds it).
    let mut kept: Vec<&str> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let l: &str = l;
        if i >= hooks_start && i < hooks_end {
            continue;
        }
        if l.starts_with("hooks_auto_accept:") && l == l.trim_start() {
            continue;
        }
        kept.push(l);
    }
    let mut cleaned = kept.join("\n");
    if existing.ends_with('\n') && !cleaned.is_empty() && !cleaned.ends_with('\n') {
        cleaned.push('\n');
    }
    Some(cleaned)
}

/// Merge the AgentKeys-managed sentinel block into a runtime config file:
///   - if the file already contains our block → replace that region only,
///   - else if a top-level `hooks:` is ours but de-sentineled (the host
///     re-serialized the YAML + dropped our comments) → adopt + re-wrap it,
///   - else if the file has a top-level `hooks:` we don't own → refuse
///     (manual merge required) so we never clobber the operator's hooks,
///   - else append our block (creating the file if absent).
fn merge_block(path: &std::path::Path, block: &str, check_only: bool) -> Result<Outcome> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();

    if let (Some(start), Some(end)) = (existing.find(BLOCK_START), existing.find(BLOCK_END)) {
        let end = end + BLOCK_END.len();
        let current_region = &existing[start..end];
        if current_region == block {
            return Ok(Outcome::Skip(format!(
                "managed block in {} matches",
                path.display()
            )));
        }
        if check_only {
            return Ok(Outcome::Ok(format!(
                "[check-only] would refresh managed block in {}",
                path.display()
            )));
        }
        let merged = format!("{}{}{}", &existing[..start], block, &existing[end..]);
        std::fs::write(path, merged).with_context(|| format!("write {}", path.display()))?;
        return Ok(Outcome::Ok(format!(
            "refreshed managed block in {}",
            path.display()
        )));
    }

    // No sentinel block. agentkeys wire OWNS the runtime's `hooks:` key (the IAM
    // guarantee requires the hooks be un-bypassable, and YAML allows only one
    // `hooks:` key), so if any top-level `hooks:` is present we REPLACE it —
    // whether it's our own block whose sentinel comments a host re-serialization
    // (`hermes config set`) dropped, or a hand-authored block. Documented for
    // users in docs/user-manual.md.
    if let Some(cleaned) = strip_top_level_hooks(&existing) {
        if check_only {
            return Ok(Outcome::Ok(format!(
                "[check-only] would replace the existing top-level `hooks:` in {} with the managed block",
                path.display()
            )));
        }
        let sep = if cleaned.is_empty() || cleaned.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        let merged = format!("{cleaned}{sep}{block}\n");
        std::fs::write(path, merged).with_context(|| format!("write {}", path.display()))?;
        return Ok(Outcome::Ok(format!(
            "replaced existing `hooks:` with the managed block in {} \
             (agentkeys wire owns this key — see docs/user-manual.md)",
            path.display()
        )));
    }

    if check_only {
        return Ok(Outcome::Ok(format!(
            "[check-only] would append managed block to {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let sep = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let merged = format!("{existing}{sep}{block}\n");
    std::fs::write(path, merged).with_context(|| format!("write {}", path.display()))?;
    Ok(Outcome::Ok(format!(
        "appended managed block to {}",
        path.display()
    )))
}

// ─── command entry point ────────────────────────────────────────────────

fn adapter_for(runtime: &str) -> Result<Box<dyn RuntimeAdapter>> {
    match runtime.to_ascii_lowercase().as_str() {
        "hermes" => Ok(Box::new(HermesAdapter::default())),
        other => anyhow::bail!(
            "no wire adapter for runtime `{other}` (Phase 1.a ships `hermes`; \
             claude-code/codex/openclaw land in Phase 1.b)"
        ),
    }
}

/// Drive `agentkeys wire <runtime>`. Returns the multi-line operator log.
pub fn cmd_wire(runtime: &str, req: WireRequest) -> Result<String> {
    let adapter = adapter_for(runtime)?;
    let bin = agentkeys_bin();
    let mut out = Vec::new();
    let mode = if req.check_only { " (check-only)" } else { "" };
    out.push(format!("[agentkeys wire {}]{mode}", adapter.name()));

    // Detect.
    match adapter.detect() {
        Some(ver) => out.push(format!("  step 0 detect: ok proceeding ({ver})")),
        None => {
            out.push(format!(
                "  step 0 detect: fail {} not installed or not on PATH",
                adapter.name()
            ));
            out.push(format!(
                "[agentkeys wire {}] aborted — install the runtime first",
                adapter.name()
            ));
            return Ok(out.join("\n"));
        }
    }

    // Apply (or diff).
    let steps = adapter.apply(&bin, &req)?;
    let mut any_fail = false;
    for (step, outcome) in &steps {
        any_fail |= outcome.is_fail();
        out.push(outcome.render(step));
    }

    // Verify (skip on check-only — we didn't write anything).
    if !req.check_only && !any_fail {
        let v = adapter.verify();
        out.push(v.render("5 verify"));
    }

    let summary = if any_fail {
        "completed WITH FAILURES — see steps above"
    } else if req.check_only {
        "drift check complete"
    } else {
        "wired — restart the runtime to load the hooks"
    };
    out.push(format!("[agentkeys wire {}] {summary}", adapter.name()));
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> WireRequest {
        WireRequest {
            actor: "O_demo_001".into(),
            operator: "O_operator_demo".into(),
            namespaces: "travel,personal".into(),
            payment_scope: "payment.spend".into(),
            mcp_url: "http://localhost:8088/mcp".into(),
            vendor_token: "demo-tok".into(),
            session_bearer: String::new(),
            memory_engine: "passthrough".into(),
            memory_max_lines: None,
            memory_engine_endpoint: None,
            memory_engine_api_key: None,
            check_only: false,
        }
    }

    #[test]
    fn unknown_runtime_errors() {
        assert!(adapter_for("nope").is_err());
    }

    #[test]
    fn hermes_adapter_resolves() {
        assert_eq!(adapter_for("hermes").unwrap().name(), "hermes");
        assert_eq!(adapter_for("HERMES").unwrap().name(), "hermes");
    }

    #[test]
    fn managed_block_is_valid_shape() {
        let a = HermesAdapter {
            home_root: Some(PathBuf::from("/tmp/agentkeys-wire-test-home")),
        };
        let block = a.managed_block(&req()).unwrap();
        assert!(block.starts_with(BLOCK_START));
        assert!(block.trim_end().ends_with(BLOCK_END));
        assert!(block.contains("pre_tool_call:"));
        assert!(block.contains("post_tool_call:"));
        assert!(block.contains("pre_llm_call:"));
        assert!(block.contains("hooks_auto_accept: true"));
        assert!(block.contains("agentkeys-pretool-permission-gate.sh"));
    }

    #[test]
    fn scripts_bake_identity_and_exec_hook() {
        let a = HermesAdapter::default();
        let scripts = a.scripts("/usr/local/bin/agentkeys", &req());
        assert_eq!(scripts.len(), 3);
        let pretool = &scripts[0].1;
        assert!(pretool.contains("AGENTKEYS_ACTOR_OMNI='O_demo_001'"));
        assert!(pretool.contains("AGENTKEYS_MCP_URL='http://localhost:8088/mcp'"));
        assert!(
            pretool.contains("exec /usr/local/bin/agentkeys hook check --scope 'payment.spend'")
        );
        assert!(scripts[1].1.contains("hook audit"));
        assert!(scripts[2]
            .1
            .contains("hook memory-inject --namespaces 'travel,personal'"));
    }

    #[test]
    fn scripts_omit_memory_engine_by_default() {
        let a = HermesAdapter::default();
        // Default passthrough + no budget → no engine env, byte-identical script.
        let scripts = a.scripts("/usr/local/bin/agentkeys", &req());
        assert!(!scripts[2].1.contains("AGENTKEYS_MEMORY_ENGINE"));
        assert!(!scripts[2].1.contains("AGENTKEYS_MEMORY_MAX_LINES"));
    }

    #[test]
    fn scripts_bake_memory_engine_when_set() {
        let a = HermesAdapter::default();
        let mut r = req();
        r.memory_engine = "lexical".into();
        r.memory_max_lines = Some(3);
        let prellm = &a.scripts("/usr/local/bin/agentkeys", &r)[2].1;
        assert!(prellm.contains("export AGENTKEYS_MEMORY_ENGINE='lexical'"));
        assert!(prellm.contains("export AGENTKEYS_MEMORY_MAX_LINES=3"));
        // engine env precedes the exec line so it is in scope for the hook
        let engine_at = prellm.find("AGENTKEYS_MEMORY_ENGINE").unwrap();
        let exec_at = prellm.find("hook memory-inject").unwrap();
        assert!(engine_at < exec_at);
    }

    #[test]
    fn scripts_bake_openviking_endpoint_only_for_openviking() {
        let a = HermesAdapter::default();
        // endpoint set but engine is lexical → OPENVIKING_* must NOT be emitted
        let mut lexical = req();
        lexical.memory_engine = "lexical".into();
        lexical.memory_engine_endpoint = Some("http://127.0.0.1:1933".into());
        assert!(!a.scripts("/usr/local/bin/agentkeys", &lexical)[2]
            .1
            .contains("OPENVIKING_ENDPOINT"));
        // engine openviking + endpoint → baked
        let mut ov = req();
        ov.memory_engine = "openviking".into();
        ov.memory_engine_endpoint = Some("http://127.0.0.1:1933".into());
        ov.memory_engine_api_key = Some("sk-ov-123".into());
        let prellm = &a.scripts("/usr/local/bin/agentkeys", &ov)[2].1;
        assert!(prellm.contains("export AGENTKEYS_MEMORY_ENGINE='openviking'"));
        assert!(prellm.contains("export OPENVIKING_ENDPOINT='http://127.0.0.1:1933'"));
        assert!(prellm.contains("export OPENVIKING_API_KEY='sk-ov-123'"));
    }

    #[test]
    fn openviking_endpoint_defaults_to_local_server_when_unset() {
        // The production default is `openviking` with NO explicit endpoint. The
        // hook's OpenVikingClient::from_env is None unless OPENVIKING_ENDPOINT is
        // set, so the wire MUST bake the local server default — else `openviking`
        // silently degrades to lexical everywhere.
        let a = HermesAdapter::default();
        let mut ov = req();
        ov.memory_engine = "openviking".into();
        ov.memory_engine_endpoint = None;
        let prellm = &a.scripts("/usr/local/bin/agentkeys", &ov)[2].1;
        assert!(prellm.contains(&format!(
            "export OPENVIKING_ENDPOINT='{}'",
            agentkeys_memory_openviking::DEFAULT_ENDPOINT
        )));
    }

    #[test]
    fn write_if_changed_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("agentkeys-wire-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("script.sh");
        let first = write_if_changed(&path, "hello", false, true).unwrap();
        assert!(matches!(first, Outcome::Ok(_)));
        let second = write_if_changed(&path, "hello", false, true).unwrap();
        assert!(matches!(second, Outcome::Skip(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_block_append_then_idempotent_then_refresh() {
        let dir = std::env::temp_dir().join(format!("agentkeys-merge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.yaml");
        std::fs::write(&cfg, "model:\n  provider: openai\n").unwrap();

        let block_v1 = format!("{BLOCK_START}\nhooks_auto_accept: true\n{BLOCK_END}");
        let a1 = merge_block(&cfg, &block_v1, false).unwrap();
        assert!(matches!(a1, Outcome::Ok(_)));
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(after.contains("model:")); // preserved
        assert!(after.contains("hooks_auto_accept: true"));

        // Re-apply same block → skip.
        let a2 = merge_block(&cfg, &block_v1, false).unwrap();
        assert!(matches!(a2, Outcome::Skip(_)));

        // Different block → refresh region, preserve outside.
        let block_v2 = format!("{BLOCK_START}\nhooks_auto_accept: false\n{BLOCK_END}");
        let a3 = merge_block(&cfg, &block_v2, false).unwrap();
        assert!(matches!(a3, Outcome::Ok(_)));
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(after.contains("model:"));
        assert!(after.contains("hooks_auto_accept: false"));
        assert!(!after.contains("hooks_auto_accept: true"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_block_replaces_foreign_hooks() {
        let dir = std::env::temp_dir().join(format!("agentkeys-foreign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.yaml");
        // A hand-authored hooks: block. agentkeys wire OWNS the hooks: key
        // (docs/user-manual.md), so it REPLACES this — never coexists.
        std::fs::write(
            &cfg,
            "model:\n  default: gpt\nhooks:\n  pre_tool_call:\n    - command: ~/my-own-hook.sh\n",
        )
        .unwrap();
        let block = format!("{BLOCK_START}\nhooks_auto_accept: true\n{BLOCK_END}");
        let outcome = merge_block(&cfg, &block, false).unwrap();
        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "should replace, not refuse"
        );
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(after.contains(BLOCK_START), "managed block installed");
        assert!(after.contains("model:"), "unrelated keys preserved");
        assert!(
            !after.contains("my-own-hook.sh"),
            "the foreign hook is replaced (wire owns the hooks: key)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_block_adopts_unsentineled_agentkeys_block() {
        let dir = std::env::temp_dir().join(format!("agentkeys-adopt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.yaml");
        // Simulate Hermes having re-serialized config.yaml: our hooks DATA is
        // present but the sentinel COMMENTS were dropped, next to an unrelated key.
        let stripped = "model:\n  default: gpt\nhooks:\n  pre_llm_call:\n    - command: ~/.hermes/agent-hooks/agentkeys-prellm-memory-inject.sh\n      timeout: 5\nhooks_auto_accept: true\n";
        std::fs::write(&cfg, stripped).unwrap();

        let block = format!("{BLOCK_START}\nhooks_auto_accept: true\n{BLOCK_END}");
        let out = merge_block(&cfg, &block, false).unwrap();
        assert!(
            matches!(out, Outcome::Ok(_)),
            "should adopt the stripped block"
        );
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(after.contains("model:"), "preserves unrelated keys");
        assert_eq!(
            after.matches(BLOCK_START).count(),
            1,
            "exactly one sentinel block"
        );
        assert!(after.contains(BLOCK_END));
        assert!(
            !after.contains("agentkeys-prellm-memory-inject.sh"),
            "the old bare hooks block is removed, not duplicated"
        );

        // Idempotent: a second run now sees the sentinels → skip.
        let again = merge_block(&cfg, &block, false).unwrap();
        assert!(matches!(again, Outcome::Skip(_)), "second run should skip");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
