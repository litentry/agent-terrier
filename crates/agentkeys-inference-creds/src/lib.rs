//! Per-family isolated loading of the three Volcano **inference** credential families (#338):
//! **ARK** (LLM, Bearer `ARK_API_KEY`), **ASR** and **TTS** (app-token `*_APP_ID` /
//! `*_ACCESS_TOKEN`). The Volcengine IAM AK/SK family (sandbox/storage, V4-signed) is NOT
//! handled here — that is the broker STS-relay path (#337).
//!
//! Isolation contract (the point of this crate):
//! - Each family resolves from its OWN two sources only: the family's process-env vars,
//!   then the family's env file `<creds-dir>/{ark,asr,tts}.env`. A loader never opens
//!   another family's file and never reads another family's vars — a leaked or rotated
//!   key in one family has zero blast radius on the other two.
//! - Precedence, identical everywhere: **process env > family file > built-in default**.
//!   Empty values (env or file) count as unset, so a stray `VAR=` can never plant an
//!   empty override.
//! - `<creds-dir>` = `$AGENTKEYS_INFERENCE_CREDS_DIR`, else `$HOME/.agentkeys/inference`
//!   (hosts: point it at `/etc/agentkeys/inference`, or let systemd `EnvironmentFile=`
//!   inject the vars — that arrives as process env here).
//! - File format: plain `KEY=VALUE` lines (`#` comments, blank lines OK; no quotes, no
//!   `export`) so ONE file feeds bash `source`, systemd `EnvironmentFile=`,
//!   `docker run --env-file`, and this loader identically. The loader tolerates
//!   `export ` prefixes and surrounding quotes defensively; writers must not rely on it.
//!
//! Rotate one family with `scripts/operator/secrets/rotate-inference-cred.sh <ark|asr|tts>`; inspect what
//! resolves from where (without printing secrets) with `volcano-probe creds`.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Overrides the directory holding the per-family env files.
pub const CREDS_DIR_ENV: &str = "AGENTKEYS_INFERENCE_CREDS_DIR";
/// Default creds dir under `$HOME`.
pub const DEFAULT_DIR_UNDER_HOME: &str = ".agentkeys/inference";

pub const DEFAULT_ARK_BASE: &str = "https://ark.cn-beijing.volces.com/api/v3";
pub const DEFAULT_ASR_RESOURCE: &str = "volc.bigasr.auc";
pub const DEFAULT_TTS_RESOURCE: &str = "volc.service_type.10029";
pub const DEFAULT_TTS_VOICE: &str = "zh_female_meilinvyou_moon_bigtts";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Ark,
    Asr,
    Tts,
}

impl Family {
    pub const ALL: [Family; 3] = [Family::Ark, Family::Asr, Family::Tts];

    pub fn name(self) -> &'static str {
        match self {
            Family::Ark => "ark",
            Family::Asr => "asr",
            Family::Tts => "tts",
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Family::Ark => "ark.env",
            Family::Asr => "asr.env",
            Family::Tts => "tts.env",
        }
    }

    /// The family's field inventory — the ONLY vars this family ever reads.
    pub fn fields(self) -> &'static [FieldSpec] {
        match self {
            Family::Ark => ARK_FIELDS,
            Family::Asr => ASR_FIELDS,
            Family::Tts => TTS_FIELDS,
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Family> {
        match s.to_ascii_lowercase().as_str() {
            "ark" | "llm" => Some(Family::Ark),
            "asr" => Some(Family::Asr),
            "tts" => Some(Family::Tts),
            _ => None,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

pub struct FieldSpec {
    pub var: &'static str,
    pub required: bool,
    pub secret: bool,
    pub default: Option<&'static str>,
}

const ARK_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        var: "ARK_API_KEY",
        required: true,
        secret: true,
        default: None,
    },
    FieldSpec {
        var: "LLM_ENDPOINT_ID",
        required: true,
        secret: false,
        default: None,
    },
    FieldSpec {
        var: "ARK_BASE_URL",
        required: false,
        secret: false,
        default: Some(DEFAULT_ARK_BASE),
    },
];

const ASR_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        var: "ASR_APP_ID",
        required: true,
        secret: false,
        default: None,
    },
    FieldSpec {
        var: "ASR_ACCESS_TOKEN",
        required: true,
        secret: true,
        default: None,
    },
    FieldSpec {
        var: "ASR_RESOURCE_ID",
        required: false,
        secret: false,
        default: Some(DEFAULT_ASR_RESOURCE),
    },
];

const TTS_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        var: "TTS_APP_ID",
        required: true,
        secret: false,
        default: None,
    },
    FieldSpec {
        var: "TTS_ACCESS_TOKEN",
        required: true,
        secret: true,
        default: None,
    },
    FieldSpec {
        var: "TTS_RESOURCE_ID",
        required: false,
        secret: false,
        default: Some(DEFAULT_TTS_RESOURCE),
    },
    FieldSpec {
        var: "TTS_VOICE_TYPE",
        required: false,
        secret: false,
        default: Some(DEFAULT_TTS_VOICE),
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Env,
    File,
    Default,
    Missing,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Source::Env => "env",
            Source::File => "file",
            Source::Default => "default",
            Source::Missing => "MISSING",
        })
    }
}

pub struct FieldReport {
    pub spec: &'static FieldSpec,
    pub source: Source,
}

pub struct FamilyReport {
    pub family: Family,
    /// The family file the loader would read (`None` when no creds dir resolves).
    pub file: Option<PathBuf>,
    pub file_exists: bool,
    pub fields: Vec<FieldReport>,
}

#[derive(Clone, Debug)]
pub struct ArkCreds {
    pub api_key: String,
    pub endpoint_id: String,
    pub base_url: String,
}

#[derive(Clone, Debug)]
pub struct AsrCreds {
    pub app_id: String,
    pub access_token: String,
    pub resource_id: String,
}

#[derive(Clone, Debug)]
pub struct TtsCreds {
    pub app_id: String,
    pub access_token: String,
    pub resource_id: String,
    pub voice_type: String,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(
        "missing {var} for the `{family}` inference family — not in the environment and not in {searched}. \
         Set it with `scripts/operator/secrets/rotate-inference-cred.sh {family}` (or export it); \
         inspect sources with `volcano-probe creds`."
    )]
    Missing {
        family: Family,
        var: &'static str,
        searched: String,
    },
    #[error("could not read {path}: {detail}")]
    FileRead { path: PathBuf, detail: String },
    #[error(
        "malformed line {line_no} in {path} (expected plain KEY=VALUE, `#` comments, blank lines)"
    )]
    FileParse { path: PathBuf, line_no: usize },
}

type EnvFn = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;
/// One resolved field: its spec, the value when present, and where it came from.
type ResolvedField = (&'static FieldSpec, Option<String>, Source);

/// Resolves each family from its own isolated sources. Construct once with
/// [`Resolver::from_process`]; tests inject env + dir via [`Resolver::with`]
/// (never mutate process env in tests).
pub struct Resolver {
    env: EnvFn,
    dir: Option<PathBuf>,
}

impl Resolver {
    pub fn from_process() -> Self {
        let env: EnvFn = Box::new(|k| std::env::var(k).ok());
        let dir = dir_from(&env);
        Resolver { env, dir }
    }

    pub fn with(env: EnvFn, dir: Option<PathBuf>) -> Self {
        Resolver { env, dir }
    }

    /// The family's env file path (whether or not it exists yet).
    pub fn family_file(&self, family: Family) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(family.file_name()))
    }

    pub fn ark(&self) -> Result<ArkCreds, Error> {
        let mut vals = self.required_values(Family::Ark)?;
        Ok(ArkCreds {
            api_key: vals.remove("ARK_API_KEY").unwrap(),
            endpoint_id: vals.remove("LLM_ENDPOINT_ID").unwrap(),
            base_url: vals.remove("ARK_BASE_URL").unwrap(),
        })
    }

    pub fn asr(&self) -> Result<AsrCreds, Error> {
        let mut vals = self.required_values(Family::Asr)?;
        Ok(AsrCreds {
            app_id: vals.remove("ASR_APP_ID").unwrap(),
            access_token: vals.remove("ASR_ACCESS_TOKEN").unwrap(),
            resource_id: vals.remove("ASR_RESOURCE_ID").unwrap(),
        })
    }

    pub fn tts(&self) -> Result<TtsCreds, Error> {
        let mut vals = self.required_values(Family::Tts)?;
        Ok(TtsCreds {
            app_id: vals.remove("TTS_APP_ID").unwrap(),
            access_token: vals.remove("TTS_ACCESS_TOKEN").unwrap(),
            resource_id: vals.remove("TTS_RESOURCE_ID").unwrap(),
            voice_type: vals.remove("TTS_VOICE_TYPE").unwrap(),
        })
    }

    /// Per-field provenance for the doctor view — never carries secret values.
    pub fn inspect(&self, family: Family) -> Result<FamilyReport, Error> {
        let resolved = self.resolve(family)?;
        Ok(FamilyReport {
            family,
            file: self.family_file(family),
            file_exists: self
                .family_file(family)
                .map(|p| p.is_file())
                .unwrap_or(false),
            fields: resolved
                .into_iter()
                .map(|(spec, _, source)| FieldReport { spec, source })
                .collect(),
        })
    }

    /// Resolve ONE var by name, consulting only the family that owns it (process env >
    /// that family's file). A var no family owns resolves from process env alone —
    /// there is no "search every file" mode, by design.
    pub fn lookup_var(&self, var: &str) -> Result<Option<(String, Source)>, Error> {
        let owner = Family::ALL
            .into_iter()
            .find(|f| f.fields().iter().any(|s| s.var == var));
        match owner {
            Some(family) => Ok(self
                .resolve(family)?
                .into_iter()
                .find(|(spec, _, _)| spec.var == var)
                .and_then(|(_, val, source)| val.map(|v| (v, source)))),
            None => Ok(non_empty((self.env)(var)).map(|v| (v, Source::Env))),
        }
    }

    /// Resolve every field of `family`: env > family file > default. Values stay
    /// internal; errors carry names/paths only.
    fn resolve(&self, family: Family) -> Result<Vec<ResolvedField>, Error> {
        let file_map = match self.family_file(family) {
            Some(path) if path.is_file() => parse_env_file_at(&path)?,
            _ => HashMap::new(),
        };
        Ok(family
            .fields()
            .iter()
            .map(|spec| {
                if let Some(v) = non_empty((self.env)(spec.var)) {
                    (spec, Some(v), Source::Env)
                } else if let Some(v) = non_empty(file_map.get(spec.var).cloned()) {
                    (spec, Some(v), Source::File)
                } else if let Some(d) = spec.default {
                    (spec, Some(d.to_string()), Source::Default)
                } else {
                    (spec, None, Source::Missing)
                }
            })
            .collect())
    }

    fn required_values(&self, family: Family) -> Result<HashMap<&'static str, String>, Error> {
        let searched = match self.family_file(family) {
            Some(p) if p.is_file() => p.display().to_string(),
            Some(p) => format!("{} (file absent)", p.display()),
            None => format!("any creds file (no dir: ${CREDS_DIR_ENV} and $HOME both unset)"),
        };
        let mut out = HashMap::new();
        for (spec, val, _) in self.resolve(family)? {
            match val {
                Some(v) => {
                    out.insert(spec.var, v);
                }
                None => {
                    return Err(Error::Missing {
                        family,
                        var: spec.var,
                        searched,
                    })
                }
            }
        }
        Ok(out)
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

fn dir_from(env: &EnvFn) -> Option<PathBuf> {
    if let Some(d) = non_empty(env(CREDS_DIR_ENV)) {
        return Some(PathBuf::from(d));
    }
    non_empty(env("HOME")).map(|h| PathBuf::from(h).join(DEFAULT_DIR_UNDER_HOME))
}

fn parse_env_file_at(path: &Path) -> Result<HashMap<String, String>, Error> {
    let content = std::fs::read_to_string(path).map_err(|e| Error::FileRead {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    parse_env_file(&content, path)
}

/// Parse `KEY=VALUE` lines. Canonical writers emit plain unquoted pairs; we
/// defensively accept an `export ` prefix and one pair of surrounding quotes.
/// Anything else is a hard error — a malformed creds file must fail loud, not
/// silently drop a key.
fn parse_env_file(content: &str, path: &Path) -> Result<HashMap<String, String>, Error> {
    let mut map = HashMap::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::FileParse {
                path: path.to_path_buf(),
                line_no: idx + 1,
            });
        };
        let key = key.trim();
        let valid_key = !key.is_empty()
            && !key.starts_with(|c: char| c.is_ascii_digit())
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid_key {
            return Err(Error::FileParse {
                path: path.to_path_buf(),
                line_no: idx + 1,
            });
        }
        map.insert(key.to_string(), unquote(value.trim()).to_string());
    }
    Ok(map)
}

fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> EnvFn {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Box::new(move |k| map.get(k).cloned())
    }

    fn write_family(dir: &Path, family: Family, content: &str) {
        std::fs::write(dir.join(family.file_name()), content).unwrap();
    }

    #[test]
    fn ark_loads_from_env_with_default_base_url() {
        let r = Resolver::with(
            env_of(&[("ARK_API_KEY", "k1"), ("LLM_ENDPOINT_ID", "ep-1")]),
            None,
        );
        let ark = r.ark().unwrap();
        assert_eq!(ark.api_key, "k1");
        assert_eq!(ark.endpoint_id, "ep-1");
        assert_eq!(ark.base_url, DEFAULT_ARK_BASE);
    }

    #[test]
    fn family_file_fills_what_env_lacks_and_env_wins_over_file() {
        let tmp = tempfile::tempdir().unwrap();
        write_family(
            tmp.path(),
            Family::Ark,
            "# ark family\nARK_API_KEY=file-key\nLLM_ENDPOINT_ID=ep-file\nARK_BASE_URL=https://file.example/api\n",
        );
        // env sets only the key -> key from env, the rest from the file.
        let r = Resolver::with(
            env_of(&[("ARK_API_KEY", "env-key")]),
            Some(tmp.path().to_path_buf()),
        );
        let ark = r.ark().unwrap();
        assert_eq!(ark.api_key, "env-key");
        assert_eq!(ark.endpoint_id, "ep-file");
        assert_eq!(ark.base_url, "https://file.example/api");
    }

    #[test]
    fn empty_values_count_as_unset() {
        let tmp = tempfile::tempdir().unwrap();
        write_family(
            tmp.path(),
            Family::Asr,
            "ASR_APP_ID=app\nASR_ACCESS_TOKEN=tok\nASR_RESOURCE_ID=\n",
        );
        // empty env var must not shadow the file; empty file var falls to default.
        let r = Resolver::with(
            env_of(&[("ASR_APP_ID", "  ")]),
            Some(tmp.path().to_path_buf()),
        );
        let asr = r.asr().unwrap();
        assert_eq!(asr.app_id, "app");
        assert_eq!(asr.resource_id, DEFAULT_ASR_RESOURCE);
    }

    #[test]
    fn missing_required_names_var_family_and_file() {
        let tmp = tempfile::tempdir().unwrap();
        let r = Resolver::with(env_of(&[]), Some(tmp.path().to_path_buf()));
        let err = r.tts().unwrap_err().to_string();
        assert!(err.contains("TTS_APP_ID"), "{err}");
        assert!(err.contains("`tts`"), "{err}");
        assert!(err.contains("tts.env"), "{err}");
        assert!(err.contains("file absent"), "{err}");
    }

    #[test]
    fn no_cross_family_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        // The ark secret sits in the WRONG family file: the ark loader must not see it.
        write_family(
            tmp.path(),
            Family::Asr,
            "ARK_API_KEY=leaked\nLLM_ENDPOINT_ID=ep-x\nASR_APP_ID=a\nASR_ACCESS_TOKEN=t\n",
        );
        let r = Resolver::with(env_of(&[]), Some(tmp.path().to_path_buf()));
        assert!(matches!(
            r.ark(),
            Err(Error::Missing {
                family: Family::Ark,
                var: "ARK_API_KEY",
                ..
            })
        ));
        // ...while the asr family still loads from its own file.
        assert_eq!(r.asr().unwrap().app_id, "a");
    }

    #[test]
    fn tts_full_family_from_file_with_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        write_family(
            tmp.path(),
            Family::Tts,
            "TTS_APP_ID=app\nexport TTS_ACCESS_TOKEN=\"tok\"\n",
        );
        let r = Resolver::with(env_of(&[]), Some(tmp.path().to_path_buf()));
        let tts = r.tts().unwrap();
        assert_eq!(tts.access_token, "tok"); // export prefix + quotes tolerated
        assert_eq!(tts.resource_id, DEFAULT_TTS_RESOURCE);
        assert_eq!(tts.voice_type, DEFAULT_TTS_VOICE);
    }

    #[test]
    fn malformed_file_fails_loud() {
        let tmp = tempfile::tempdir().unwrap();
        write_family(tmp.path(), Family::Ark, "ARK_API_KEY=k\nnot a pair\n");
        let r = Resolver::with(env_of(&[]), Some(tmp.path().to_path_buf()));
        match r.ark() {
            Err(Error::FileParse { line_no, .. }) => assert_eq!(line_no, 2),
            other => panic!("expected FileParse, got {other:?}"),
        }
    }

    #[test]
    fn inspect_reports_sources_without_values() {
        let tmp = tempfile::tempdir().unwrap();
        write_family(tmp.path(), Family::Ark, "LLM_ENDPOINT_ID=ep-file\n");
        let r = Resolver::with(
            env_of(&[("ARK_API_KEY", "k")]),
            Some(tmp.path().to_path_buf()),
        );
        let rep = r.inspect(Family::Ark).unwrap();
        assert!(rep.file_exists);
        let src = |var: &str| {
            rep.fields
                .iter()
                .find(|f| f.spec.var == var)
                .unwrap()
                .source
                .clone()
        };
        assert_eq!(src("ARK_API_KEY"), Source::Env);
        assert_eq!(src("LLM_ENDPOINT_ID"), Source::File);
        assert_eq!(src("ARK_BASE_URL"), Source::Default);
    }

    #[test]
    fn inspect_flags_missing() {
        let r = Resolver::with(env_of(&[]), None);
        let rep = r.inspect(Family::Asr).unwrap();
        assert!(!rep.file_exists);
        assert!(rep.file.is_none());
        assert!(rep
            .fields
            .iter()
            .any(|f| f.spec.var == "ASR_ACCESS_TOKEN" && f.source == Source::Missing));
    }

    #[test]
    fn lookup_var_consults_owning_family_only() {
        let tmp = tempfile::tempdir().unwrap();
        write_family(tmp.path(), Family::Ark, "LLM_ENDPOINT_ID=ep-file\n");
        write_family(tmp.path(), Family::Tts, "SEARCH_MODEL=wrong-owner\n");
        let r = Resolver::with(
            env_of(&[("SEARCH_MODEL", "from-env")]),
            Some(tmp.path().to_path_buf()),
        );
        // family-owned var: found in its own file.
        let (v, s) = r.lookup_var("LLM_ENDPOINT_ID").unwrap().unwrap();
        assert_eq!((v.as_str(), s), ("ep-file", Source::File));
        // unowned var: process env only — the tts.env copy is invisible.
        let (v, s) = r.lookup_var("SEARCH_MODEL").unwrap().unwrap();
        assert_eq!((v.as_str(), s), ("from-env", Source::Env));
        assert!(r.lookup_var("UNSET_VAR").unwrap().is_none());
    }

    #[test]
    fn dir_resolution_prefers_override_env() {
        let env = env_of(&[(CREDS_DIR_ENV, "/etc/agentkeys/inference"), ("HOME", "/h")]);
        assert_eq!(
            dir_from(&env),
            Some(PathBuf::from("/etc/agentkeys/inference"))
        );
        let env = env_of(&[("HOME", "/h")]);
        assert_eq!(
            dir_from(&env),
            Some(PathBuf::from("/h").join(DEFAULT_DIR_UNDER_HOME))
        );
        assert_eq!(dir_from(&env_of(&[])), None);
    }
}
