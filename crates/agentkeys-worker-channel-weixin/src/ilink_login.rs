//! The interactive iLink QR login ceremony (`--login`) — the operator-run
//! equivalent of `openclaw channels login`. Mirrors the upstream plugin's
//! login-qr.ts state machine:
//!
//! 1. `get_bot_qrcode` (bootstrap host) → render the QR in the terminal; the
//!    operator scans it with the SPARE personal-WeChat account's phone.
//! 2. Long-poll `get_qrcode_status` (1 s cadence): `scaned` → verifying;
//!    `need_verifycode` → the phone shows a pairing number, type it here;
//!    `scaned_but_redirect` → switch polling to the per-IDC host; `expired` →
//!    refresh the QR (max 3); `binded_redirect` → already connected (success,
//!    existing credentials stay valid); `confirmed` → done.
//! 3. On `confirmed`, return the minted credentials. The caller either PRINTS
//!    them for the operator to merge (`--login`), or upserts them directly into
//!    the gateway secrets file (`--login-write`, rebind-safe) — #384 custody;
//!    the token NEVER enters any agent env.

use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};

use crate::ilink::{IlinkClient, ILINK_BOOTSTRAP_BASE_URL};

const OVERALL_DEADLINE: Duration = Duration::from_secs(480);
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_QR_REFRESH: u32 = 3;

/// Canonical secrets-file default for `--login-write` (override with
/// `--secrets-file`). Kept in sync with `setup-broker-host.sh`'s
/// `WORKER_WEIXIN_SECRETS_FILE` (`$DEV_KEY_SERVICE_ENV_DIR/weixin-secrets.env`).
pub const DEFAULT_SECRETS_FILE: &str = "/etc/agentkeys/weixin-secrets.env";

/// The keys `--login-write` OWNS in the secrets file. Every other line (the OA
/// creds, `AGENTKEYS_WEIXIN_OPERATOR_OMNI`, the admin token, comments) is
/// preserved verbatim by the upsert.
const MANAGED_KEYS: [&str; 3] = [
    "AGENTKEYS_WEIXIN_TRANSPORT",
    "AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN",
    "AGENTKEYS_WEIXIN_ILINK_BASE_URL",
];
const PROVENANCE_PREFIX: &str = "# ilink_bot_id=";

pub struct LoginOutcome {
    pub bot_token: String,
    pub base_url: String,
    pub bot_id: String,
    pub scanned_by: String,
}

/// Run the ceremony. `existing_tokens` (from a previously-filled secrets env)
/// lets the server detect an already-bound bot instead of double-binding.
/// Returns `Some(outcome)` on a fresh `confirmed` bind (the caller persists it),
/// or `None` when the account was already bound (`binded_redirect` — the server
/// returns no new token, so there is nothing to write).
pub async fn run_login(
    bootstrap_base_url: &str,
    existing_tokens: Vec<String>,
) -> anyhow::Result<Option<LoginOutcome>> {
    let bootstrap = if bootstrap_base_url.trim().is_empty() {
        ILINK_BOOTSTRAP_BASE_URL
    } else {
        bootstrap_base_url
    };
    let client = IlinkClient::new(bootstrap, None, "AgentKeys-login");

    let mut qr = client
        .get_bot_qrcode(&existing_tokens)
        .await
        .context("fetching the login QR code (is the host reachable?)")?;
    println!("\n用手机微信扫描以下二维码，以连接 AgentKeys 网关：\n");
    print_qr(&qr.qrcode_img_content);

    // The status long-poll may redirect to a per-IDC host mid-ceremony.
    let mut poll = IlinkClient::new(bootstrap, None, "AgentKeys-login");
    let mut verify_code: Option<String> = None;
    let mut refreshes: u32 = 1;
    let mut said_verifying = false;
    let started = Instant::now();

    while started.elapsed() < OVERALL_DEADLINE {
        let status = poll
            .get_qrcode_status(&qr.qrcode, verify_code.as_deref())
            .await;
        match status.status.as_str() {
            "wait" => {
                print!(".");
                std::io::stdout().flush().ok();
            }
            "scaned" => {
                verify_code = None; // an accepted code stops being re-sent
                if !said_verifying {
                    println!("\n已扫码，正在验证…");
                    said_verifying = true;
                }
            }
            "need_verifycode" => {
                let prompt = if verify_code.is_some() {
                    "❌ 数字不匹配，请重新输入手机微信显示的数字："
                } else {
                    "输入手机微信显示的数字，以继续连接："
                };
                verify_code = Some(read_line(prompt).await?);
                continue; // poll again immediately with the code attached
            }
            "verify_code_blocked" => {
                println!("\n⛔ 多次输入错误。");
                verify_code = None;
                refreshes += 1;
                if refreshes > MAX_QR_REFRESH {
                    bail!("多次输入错误，连接流程已停止。请稍后再试。");
                }
                qr = client.get_bot_qrcode(&existing_tokens).await?;
                said_verifying = false;
                println!("🔄 二维码已更新，请重新扫描：\n");
                print_qr(&qr.qrcode_img_content);
            }
            "expired" => {
                refreshes += 1;
                if refreshes > MAX_QR_REFRESH {
                    bail!("二维码多次失效，连接流程已停止。请稍后再试。");
                }
                qr = client.get_bot_qrcode(&existing_tokens).await?;
                said_verifying = false;
                println!("\n🔄 二维码已过期并更新，请重新扫描：\n");
                print_qr(&qr.qrcode_img_content);
            }
            "scaned_but_redirect" => {
                if let Some(host) = status.redirect_host.as_deref().filter(|h| !h.is_empty()) {
                    let new_base = format!("https://{host}");
                    println!("\n（切换到就近接入点 {host}）");
                    poll = IlinkClient::new(&new_base, None, "AgentKeys-login");
                }
            }
            "binded_redirect" => {
                println!("\n✅ 该微信号已连接过此网关，现有凭据仍然有效，无需重复连接。");
                return Ok(None);
            }
            "confirmed" => {
                // Mirror the upstream plugin's guard: a `confirmed` WITHOUT an
                // `ilink_bot_id` is NOT a completed bind (the plugin hard-fails
                // "登录失败：服务器未返回 ilink_bot_id"). Refuse it loudly rather
                // than writing a half-bound token that looks connected but never
                // receives — the operator must finish the on-phone authorization.
                let bot_id = status
                    .ilink_bot_id
                    .clone()
                    .filter(|b| !b.is_empty())
                    .context(
                        "登录未完成：服务器返回 confirmed 但缺少 ilink_bot_id。\
                         请在手机微信上点“连接/授权”完成绑定后重试。",
                    )?;
                let bot_token = status
                    .bot_token
                    .filter(|t| !t.is_empty())
                    .context("登录已确认但服务器未返回 bot_token")?;
                let outcome = LoginOutcome {
                    bot_token,
                    base_url: status
                        .baseurl
                        .filter(|b| !b.is_empty())
                        .unwrap_or_else(|| poll.base_url.clone()),
                    bot_id,
                    scanned_by: status.ilink_user_id.unwrap_or_default(),
                };
                return Ok(Some(outcome));
            }
            other => {
                println!("\n（未知状态 {other}，继续等待…）");
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    bail!("登录超时（8 分钟内未完成扫码确认），请重试。")
}

fn print_qr(url: &str) {
    match qrcode::QrCode::new(url.as_bytes()) {
        Ok(code) => {
            let rendered = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            println!("{rendered}");
        }
        Err(e) => eprintln!("（二维码渲染失败：{e}）"),
    }
    println!("若二维码无法扫描，可在手机上直接打开此链接继续：\n{url}\n");
}

async fn read_line(prompt: &str) -> anyhow::Result<String> {
    print!("\n{prompt}");
    std::io::stdout().flush().ok();
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading stdin")?;
        Ok::<String, anyhow::Error>(line.trim().to_string())
    })
    .await
    .context("stdin task")?
}

/// The post-login "bring the bot online" instruction. Login only mints + saves
/// the token; WeChat shows the bot as "connected" ONLY once the gateway PROCESS
/// runs (it sends `notifystart` + long-polls `getupdates`) — exactly like the
/// upstream plugin's "restart the gateway after login" step. systemd drives it
/// on the broker host; a laptop has no `systemctl`, so it's a direct run there.
pub fn next_step_hint(secrets_path: &Path) -> String {
    let systemd = Path::new("/run/systemd/system").exists();
    if systemd {
        "下一步：重启网关让 bot 上线（登录只保存了凭据，网关进程运行后 WeChat 才显示“已连接”）：\n  \
         sudo systemctl restart agentkeys-worker-channel-weixin"
            .to_string()
    } else {
        format!(
            "下一步：登录只保存了凭据——WeChat 要等网关“进程”运行后才显示“已连接”。\n  \
             · broker host：sudo systemctl restart agentkeys-worker-channel-weixin\n  \
             · 本地/开发（本机无 systemctl）：source 凭据后直接运行 worker——\n      \
             set -a; . {}; set +a\n      \
             cargo run -p agentkeys-worker-channel-weixin\n    \
             （本地运行还需 AGENTKEYS_WEIXIN_OPERATOR_OMNI 和 AGENTKEYS_WEIXIN_CONTACT_REGISTRY_FILE）",
            secrets_path.display()
        )
    }
}

/// PRINT the minted lines for the operator to merge by hand (plain `--login`),
/// optionally dumping the standalone block to `out` (`--login-out`, `0600`).
pub fn print_secrets(outcome: &LoginOutcome, out: Option<&Path>) -> anyhow::Result<()> {
    let lines = format!(
        "AGENTKEYS_WEIXIN_TRANSPORT=ilink\n\
         AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN={}\n\
         AGENTKEYS_WEIXIN_ILINK_BASE_URL={}\n\
         {PROVENANCE_PREFIX}{} scanned_by={}\n",
        outcome.bot_token, outcome.base_url, outcome.bot_id, outcome.scanned_by
    );
    println!(
        "\n✅ 已连接。将下列几行合并进 {DEFAULT_SECRETS_FILE}（#384 custody）：\n\n{lines}\n{}\n\
         （提示：加 `--login-write` 可自动写入并覆盖旧绑定，无需手工合并。）",
        next_step_hint(Path::new(DEFAULT_SECRETS_FILE))
    );
    if let Some(path) = out {
        std::fs::write(path, &lines)
            .with_context(|| format!("writing login output {}", path.display()))?;
        set_0600(path)?;
        println!("（已写入 {} — 0600）", path.display());
    }
    Ok(())
}

/// UPSERT the minted credentials directly into the gateway secrets file
/// (`--login-write`). Rebind-safe: the three [`MANAGED_KEYS`] and the provenance
/// comment are overwritten in place; every other line (OA creds, operator omni,
/// admin token, comments) is preserved. Returns `true` when a *real* prior bot
/// token was replaced (a rebind, vs first-filling the `REPLACE_ME` placeholder).
///
/// The write is in-place (`O_TRUNC`), so the file's existing owner — `agentkeys`,
/// per the systemd unit — and inode are preserved; mode is re-asserted `0600`.
pub fn write_secrets_file(path: &Path, outcome: &LoginOutcome) -> anyhow::Result<bool> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            String::new()
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading {}", path.display()));
        }
    };
    let (content, rebound) = upsert_env(&existing, outcome);
    std::fs::write(path, &content).with_context(|| format!("writing {}", path.display()))?;
    set_0600(path)?;
    Ok(rebound)
}

/// #502 (plan T9): persist the CONNECT-recorded operator omni into the same
/// secrets file, in place — replaces an existing `AGENTKEYS_WEIXIN_OPERATOR_OMNI=`
/// line (placeholder or armed; the caller already warned loudly on an override)
/// or appends one; every other line is preserved. Returns `true` when a real
/// (non-placeholder, non-equal) prior value was replaced. Same `0600` +
/// in-place-write posture as [`write_secrets_file`].
pub fn upsert_operator_omni(path: &Path, omni: &str) -> anyhow::Result<bool> {
    const KEY: &str = "AGENTKEYS_WEIXIN_OPERATOR_OMNI";
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            String::new()
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };

    let mut seen = false;
    let mut replaced_armed = false;
    let mut out_lines: Vec<String> = Vec::new();
    for line in existing.lines() {
        let body = {
            let t = line.trim_start();
            t.strip_prefix("export ").unwrap_or(t)
        };
        if let Some(rest) = body.strip_prefix(KEY).filter(|r| r.starts_with('=')) {
            let old = rest[1..].trim();
            if !old.is_empty() && !old.starts_with("REPLACE_ME") && old != omni {
                replaced_armed = true;
            }
            out_lines.push(format!("{KEY}={omni}"));
            seen = true;
            continue;
        }
        out_lines.push(line.to_string());
    }
    if !seen {
        out_lines.push(format!("{KEY}={omni}"));
    }
    let mut content = out_lines.join("\n");
    content.push('\n');
    std::fs::write(path, &content).with_context(|| format!("writing {}", path.display()))?;
    set_0600(path)?;
    Ok(replaced_armed)
}

/// Blank the persisted iLink token (operator DISCONNECT) so a restart stays
/// OFFLINE until the next login. In-place rewrite that keeps every non-managed
/// line (admin token, operator omni, OA creds, comments) — only the managed
/// `BOT_TOKEN`/`BASE_URL` are emptied. `config::secret_from_env` treats an empty
/// token as UNSET, so the next boot idles instead of long-polling with a dead
/// token. No-op if the file doesn't exist.
pub fn clear_secrets_file(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let cleared = LoginOutcome {
        bot_token: String::new(),
        base_url: String::new(),
        bot_id: String::new(),
        scanned_by: String::new(),
    };
    write_secrets_file(path, &cleared)?;
    Ok(())
}

fn set_0600(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn managed_value(key: &str, outcome: &LoginOutcome) -> String {
    match key {
        "AGENTKEYS_WEIXIN_TRANSPORT" => "ilink".to_string(),
        "AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN" => outcome.bot_token.clone(),
        "AGENTKEYS_WEIXIN_ILINK_BASE_URL" => outcome.base_url.clone(),
        _ => unreachable!("managed_value called with non-managed key {key}"),
    }
}

/// Pure env-file merge (unit-tested). Replaces the managed keys in place,
/// appends any that were absent (canonical order), and reports whether a real
/// prior token was overwritten.
fn upsert_env(existing: &str, outcome: &LoginOutcome) -> (String, bool) {
    let provenance = format!(
        "{PROVENANCE_PREFIX}{} scanned_by={}",
        outcome.bot_id, outcome.scanned_by
    );
    let mut seen = [false; MANAGED_KEYS.len()];
    let mut seen_provenance = false;
    let mut rebound = false;
    let mut out_lines: Vec<String> = Vec::new();

    for line in existing.lines() {
        let body = {
            let t = line.trim_start();
            t.strip_prefix("export ").unwrap_or(t)
        };
        let mut replaced = false;
        for (i, key) in MANAGED_KEYS.iter().enumerate() {
            // The `=` guard prevents a shorter key matching a longer one's prefix.
            if let Some(rest) = body.strip_prefix(key).filter(|r| r.starts_with('=')) {
                if *key == "AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN" {
                    let old = rest[1..].trim();
                    if !old.is_empty() && !old.starts_with("REPLACE_ME") && old != outcome.bot_token
                    {
                        rebound = true;
                    }
                }
                out_lines.push(format!("{key}={}", managed_value(key, outcome)));
                seen[i] = true;
                replaced = true;
                break;
            }
        }
        if replaced {
            continue;
        }
        if body.starts_with(PROVENANCE_PREFIX) {
            out_lines.push(provenance.clone());
            seen_provenance = true;
            continue;
        }
        out_lines.push(line.to_string());
    }

    for (i, key) in MANAGED_KEYS.iter().enumerate() {
        if !seen[i] {
            out_lines.push(format!("{key}={}", managed_value(key, outcome)));
        }
    }
    if !seen_provenance {
        out_lines.push(provenance);
    }

    let mut content = out_lines.join("\n");
    content.push('\n');
    (content, rebound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(token: &str) -> LoginOutcome {
        LoginOutcome {
            bot_token: token.to_string(),
            base_url: "https://ilinkai.weixin.qq.com".to_string(),
            bot_id: "fe17118b3cbe@im.bot".to_string(),
            scanned_by: "o9cq803h0qm@im.wechat".to_string(),
        }
    }

    #[test]
    fn fills_placeholder_template_without_flagging_rebind() {
        let template = "\
AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc
AGENTKEYS_WEIXIN_TRANSPORT=ilink
AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=REPLACE_ME_from_--login
AGENTKEYS_WEIXIN_ILINK_BASE_URL=REPLACE_ME_from_--login
AGENTKEYS_WEIXIN_ADMIN_TOKEN=deadbeef
";
        let (out, rebound) = upsert_env(template, &outcome("tok-1@im.bot:secret"));
        assert!(!rebound, "filling a REPLACE_ME placeholder is not a rebind");
        assert!(out.contains("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=tok-1@im.bot:secret"));
        assert!(out.contains("AGENTKEYS_WEIXIN_ILINK_BASE_URL=https://ilinkai.weixin.qq.com"));
        // unmanaged lines preserved verbatim
        assert!(out.contains("AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc"));
        assert!(out.contains("AGENTKEYS_WEIXIN_ADMIN_TOKEN=deadbeef"));
        // no leftover placeholder, exactly one token line
        assert!(!out.contains("REPLACE_ME"));
        assert_eq!(
            out.matches("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=").count(),
            1,
            "must not duplicate the token key"
        );
        assert!(out.contains("# ilink_bot_id=fe17118b3cbe@im.bot scanned_by=o9cq803h0qm@im.wechat"));
    }

    #[test]
    fn rebind_overwrites_existing_real_token_in_place() {
        let existing = "\
AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc
AGENTKEYS_WEIXIN_TRANSPORT=ilink
AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=old-real@im.bot:oldsecret
AGENTKEYS_WEIXIN_ILINK_BASE_URL=https://old.example
# ilink_bot_id=old@im.bot scanned_by=olduser@im.wechat
";
        let (out, rebound) = upsert_env(existing, &outcome("new@im.bot:newsecret"));
        assert!(rebound, "replacing a real prior token IS a rebind");
        assert!(!out.contains("old-real@im.bot:oldsecret"));
        assert!(out.contains("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=new@im.bot:newsecret"));
        assert!(out.contains("AGENTKEYS_WEIXIN_ILINK_BASE_URL=https://ilinkai.weixin.qq.com"));
        assert!(!out.contains("https://old.example"));
        assert!(out.contains("AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc"));
        // provenance replaced, not duplicated
        assert_eq!(out.matches("# ilink_bot_id=").count(), 1);
        assert!(!out.contains("old@im.bot"));
    }

    #[test]
    fn appends_all_keys_into_empty_or_oa_only_file() {
        let oa_only = "\
AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc
AGENTKEYS_WEIXIN_TOKEN=cbtok
AGENTKEYS_WEIXIN_APP_ID=wxappid
";
        let (out, rebound) = upsert_env(oa_only, &outcome("fresh@im.bot:sec"));
        assert!(!rebound);
        assert!(out.contains("AGENTKEYS_WEIXIN_TRANSPORT=ilink"));
        assert!(out.contains("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=fresh@im.bot:sec"));
        assert!(out.contains("AGENTKEYS_WEIXIN_ILINK_BASE_URL=https://ilinkai.weixin.qq.com"));
        // OA lines untouched (transport flip is intentional — operator is switching)
        assert!(out.contains("AGENTKEYS_WEIXIN_TOKEN=cbtok"));
        assert!(out.contains("AGENTKEYS_WEIXIN_APP_ID=wxappid"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn empty_file_gets_full_block() {
        let (out, rebound) = upsert_env("", &outcome("t@im.bot:s"));
        assert!(!rebound);
        for key in MANAGED_KEYS {
            assert_eq!(out.matches(&format!("{key}=")).count(), 1);
        }
        assert!(out.contains("# ilink_bot_id="));
    }

    #[test]
    fn write_secrets_file_round_trip_fills_then_rebinds_and_is_0600() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ak-weixin-secrets-{}-{}.env",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        // Seed the placeholder template exactly as setup-broker-host.sh ships it.
        std::fs::write(
            &path,
            "AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc\n\
             AGENTKEYS_WEIXIN_TRANSPORT=ilink\n\
             AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=REPLACE_ME_from_--login\n\
             AGENTKEYS_WEIXIN_ILINK_BASE_URL=REPLACE_ME_from_--login\n",
        )
        .unwrap();

        // First bind: fills the placeholder — NOT a rebind.
        let rebound = write_secrets_file(&path, &outcome("tok-A@im.bot:s")).unwrap();
        assert!(!rebound);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN=tok-A@im.bot:s"));
        assert!(after.contains("AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc"));
        assert!(!after.contains("REPLACE_ME"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "secrets file must be 0600");
        }

        // Second run, new token: overwrites in place — IS a rebind, omni preserved.
        let rebound2 = write_secrets_file(&path, &outcome("tok-B@im.bot:s")).unwrap();
        assert!(rebound2);
        let after2 = std::fs::read_to_string(&path).unwrap();
        assert!(after2.contains("tok-B@im.bot:s"));
        assert!(!after2.contains("tok-A@im.bot:s"));
        assert!(after2.contains("AGENTKEYS_WEIXIN_OPERATOR_OMNI=0xabc"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_operator_omni_appends_replaces_and_preserves() {
        let path = std::env::temp_dir().join(format!("ak-omni-upsert-{}.env", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let omni_a = format!("0x{}", "aa".repeat(32));
        let omni_b = format!("0x{}", "bb".repeat(32));

        // Fresh file → appended, not an armed replacement.
        assert!(!super::upsert_operator_omni(&path, &omni_a).unwrap());
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains(&format!("AGENTKEYS_WEIXIN_OPERATOR_OMNI={omni_a}")));

        // Placeholder + other lines: placeholder filled, everything else kept,
        // still not an armed replacement.
        std::fs::write(
            &path,
            "# comment stays\nAGENTKEYS_WEIXIN_ADMIN_TOKEN=tok\n\
             export AGENTKEYS_WEIXIN_OPERATOR_OMNI=REPLACE_ME_operator_omni_0x64hex\n",
        )
        .unwrap();
        assert!(!super::upsert_operator_omni(&path, &omni_a).unwrap());
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains("# comment stays"));
        assert!(s.contains("AGENTKEYS_WEIXIN_ADMIN_TOKEN=tok"));
        assert!(s.contains(&format!("AGENTKEYS_WEIXIN_OPERATOR_OMNI={omni_a}")));
        assert!(!s.contains("REPLACE_ME_operator_omni"));

        // A DIFFERENT armed value → replaced, reported as an armed replacement
        // (the caller's loud-override warn pairs with this).
        assert!(super::upsert_operator_omni(&path, &omni_b).unwrap());
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains(&format!("AGENTKEYS_WEIXIN_OPERATOR_OMNI={omni_b}")));
        assert!(!s.contains(&omni_a));

        // Same value again → idempotent, not an armed replacement.
        assert!(!super::upsert_operator_omni(&path, &omni_b).unwrap());

        let _ = std::fs::remove_file(&path);
    }
}
