//! The API contract (INTERFACES.md §11.7): `windows/api/paguro-api.json`
//! against the Rust side.
//!
//! - every method of [`rpc::METHODS`] is in the schema and vice versa, with
//!   the same access, gated parameters, dry-run rule, progress and stub flag;
//! - each method's parameter struct accepts exactly the schema's parameters;
//! - every example request validates, runs against the demo machine, and
//!   its response validates against the method's result (or the error
//!   schema); the exchanges are the fixtures the C# contract test replays
//!   (`windows/api/fixtures/`, regenerated with `PAGURO_BLESS=1`);
//! - every method has a CLI command (`cli_example` parses to it).
//!
//! The validator covers the subset of JSON Schema the file uses: `type`
//! (with `null` unions), `properties`, `required`, `additionalProperties:
//! false`, `items`, `enum`, `anyOf`, `minimum`, local `$ref`.
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Parser;
use paguro_win::mock::MockApi;
use paguro_win::rpc::{self, Access, Caller};
use serde_json::{Map, Value, json};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../windows/api")
}

fn schema() -> Value {
    let s = std::fs::read_to_string(root().join("paguro-api.json")).expect("paguro-api.json");
    serde_json::from_str(&s).expect("paguro-api.json is JSON")
}

struct V<'a> {
    defs: &'a Map<String, Value>,
}

impl V<'_> {
    fn resolve<'b>(&'b self, s: &'b Value) -> &'b Value {
        match s.get("$ref").and_then(Value::as_str) {
            Some(r) => {
                let name = r.strip_prefix("#/$defs/").expect("local $ref");
                self.resolve(self.defs.get(name).unwrap_or_else(|| panic!("no $defs/{name}")))
            }
            None => s,
        }
    }

    fn type_ok(t: &str, v: &Value) -> bool {
        match t {
            "null" => v.is_null(),
            "boolean" => v.is_boolean(),
            "string" => v.is_string(),
            "integer" => v.is_i64() || v.is_u64(),
            "number" => v.is_number(),
            "array" => v.is_array(),
            "object" => v.is_object(),
            _ => panic!("unknown type {t}"),
        }
    }

    fn check(&self, s: &Value, v: &Value, at: &str, errs: &mut Vec<String>) {
        let s = self.resolve(s);
        if let Some(any) = s.get("anyOf").and_then(Value::as_array) {
            let ok = any.iter().any(|a| {
                let mut e = Vec::new();
                self.check(a, v, at, &mut e);
                e.is_empty()
            });
            if !ok {
                errs.push(format!("{at}: matches no anyOf branch: {v}"));
            }
            return;
        }
        match s.get("type") {
            Some(Value::String(t)) if !Self::type_ok(t, v) => {
                errs.push(format!("{at}: expected {t}, got {v}"));
                return;
            }
            Some(Value::Array(ts)) if !ts.iter().any(|t| Self::type_ok(t.as_str().unwrap_or(""), v)) => {
                errs.push(format!("{at}: expected one of {ts:?}, got {v}"));
                return;
            }
            _ => {}
        }
        if let (Some(e), false) = (s.get("enum").and_then(Value::as_array), v.is_null()) {
            if !e.contains(v) {
                errs.push(format!("{at}: {v} not in {e:?}"));
            }
        }
        if let (Some(min), Some(n)) = (s.get("minimum").and_then(Value::as_i64), v.as_i64()) {
            if n < min {
                errs.push(format!("{at}: {n} < {min}"));
            }
        }
        if let Some(o) = v.as_object() {
            let props = s.get("properties").and_then(Value::as_object);
            for r in s.get("required").and_then(Value::as_array).into_iter().flatten() {
                let r = r.as_str().unwrap_or("");
                if !o.contains_key(r) {
                    errs.push(format!("{at}: missing required {r}"));
                }
            }
            for (k, x) in o {
                match props.and_then(|p| p.get(k)) {
                    Some(ps) => self.check(ps, x, &format!("{at}.{k}"), errs),
                    None if s.get("additionalProperties") == Some(&Value::Bool(false)) => {
                        errs.push(format!("{at}: unknown property {k}"));
                    }
                    None => {}
                }
            }
        }
        if let (Some(a), Some(items)) = (v.as_array(), s.get("items")) {
            for (i, x) in a.iter().enumerate() {
                self.check(items, x, &format!("{at}[{i}]"), errs);
            }
        }
    }

    fn validate(&self, s: &Value, v: &Value, at: &str) {
        let mut errs = Vec::new();
        self.check(s, v, at, &mut errs);
        assert!(errs.is_empty(), "{}", errs.join("\n"));
    }
}

fn admin() -> Caller {
    Caller {
        user: "contract".into(),
        admin: true,
        elevated: true,
        pid: None,
    }
}

fn access(a: Access) -> &'static str {
    match a {
        Access::Read => "read",
        Access::Admin => "admin",
        Access::Elevated => "elevated",
    }
}

#[test]
fn methods_match_the_schema() {
    let s = schema();
    let methods = s["methods"].as_object().expect("methods");
    let rust: BTreeSet<&str> = rpc::METHODS.iter().map(|m| m.name).collect();
    let json: BTreeSet<&str> = methods.keys().map(String::as_str).collect();
    assert_eq!(rust, json, "rpc::METHODS and paguro-api.json disagree");
    for m in rpc::METHODS {
        let d = &methods[m.name];
        assert_eq!(d["access"], access(m.access), "{}: access", m.name);
        let gated: Vec<&str> = d["gated"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        assert_eq!(gated, m.gated, "{}: gated", m.name);
        assert_eq!(d["dry_run_read"] == true, m.dry_run_read, "{}: dry_run_read", m.name);
        assert_eq!(d["progress"] == true, m.progress, "{}: progress", m.name);
        assert_eq!(d["stub"].is_string(), m.stub, "{}: stub", m.name);
        assert!(d["cmdlets"].as_array().is_some_and(|a| !a.is_empty()), "{}: a cmdlet", m.name);
    }
    assert_eq!(s["version"], rpc::API_VERSION);
}

/// The fields a Rust parameter struct accepts, from serde's own refusal of
/// an unknown one.
fn rust_fields(method: &str) -> BTreeSet<String> {
    let api = MockApi::demo();
    let o = rpc::Options {
        caller: admin(),
        enforce: true,
        interactive: false,
        passphrase_stdin: false,
        service: true,
        progress: None,
    };
    let e = rpc::call(&api, method, &json!({ "__probe__": 1 }), &o).expect_err("probe must fail");
    assert_eq!(e.code, rpc::codes::INVALID_PARAMS, "{method}: {}", e.message);
    let msg = e.message;
    if msg.contains("there are no fields") {
        return BTreeSet::new();
    }
    let tail = msg.split("expected").nth(1).unwrap_or_else(|| panic!("{method}: {msg}"));
    tail.split('`')
        .skip(1)
        .step_by(2)
        .map(String::from)
        .collect()
}

#[test]
fn params_match_the_schema() {
    let s = schema();
    let defs = s["$defs"].as_object().expect("$defs");
    let v = V { defs };
    let common: BTreeSet<String> = defs["CommonParams"]["properties"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(common, rpc::COMMON.iter().map(|c| c.to_string()).collect());
    for (name, d) in s["methods"].as_object().unwrap() {
        let p = v.resolve(&d["params"]);
        assert_eq!(p["additionalProperties"], false, "{name}: params are closed");
        let declared: BTreeSet<String> = p["properties"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        assert_eq!(declared, rust_fields(name), "{name}: schema params vs the Rust struct");
        // The examples exercise every parameter.
        let mut seen = BTreeSet::new();
        for ex in d["examples"].as_array().expect("examples") {
            let mut own = ex.as_object().unwrap().clone();
            own.retain(|k, _| !common.contains(k));
            seen.extend(own.keys().cloned());
            v.validate(&d["params"], &Value::Object(own), &format!("{name} example"));
        }
        assert!(declared.is_subset(&seen), "{name}: examples miss {:?}", declared.difference(&seen).collect::<Vec<_>>());
    }
}

#[test]
fn responses_match_the_schema_and_the_fixtures() {
    let s = schema();
    let defs = s["$defs"].as_object().expect("$defs");
    let v = V { defs };
    let bless = std::env::var_os("PAGURO_BLESS").is_some();
    let dir = root().join("fixtures");
    let mut stale = Vec::new();
    let mut expected = BTreeSet::new();
    for (name, d) in s["methods"].as_object().unwrap() {
        for (i, ex) in d["examples"].as_array().unwrap().iter().enumerate() {
            let api = MockApi::demo();
            let req = json!({ "jsonrpc": "2.0", "id": 1, "method": name, "params": ex });
            let notes = std::cell::RefCell::new(Vec::new());
            let resp = rpc::handle_line(&api, &req.to_string(), &admin(), true, &|n| notes.borrow_mut().push(n.clone()))
                .expect("a response");
            if let Some(r) = resp.get("result") {
                v.validate(&json!({ "$ref": "#/$defs/Result" }), r, &format!("{name} result"));
                v.validate(&d["result"], &r["data"], &format!("{name} data"));
            } else {
                let e = &resp["error"];
                let code = e["code"].as_i64().unwrap_or(0);
                assert!(
                    code != rpc::codes::INVALID_PARAMS && code != rpc::codes::METHOD_NOT_FOUND,
                    "{name} example {i}: {e}"
                );
                v.validate(&json!({ "$ref": "#/$defs/ErrorData" }), &e["data"], &format!("{name} error"));
            }
            for n in notes.borrow().iter() {
                assert_eq!(n["method"], "progress");
                v.validate(&json!({ "$ref": "#/$defs/Progress" }), &n["params"], &format!("{name} progress"));
            }
            let fx = json!({
                "method": name,
                "request": req,
                "notifications": *notes.borrow(),
                "response": resp,
            });
            let file = if i == 0 { format!("{name}.json") } else { format!("{name}.{i}.json") };
            expected.insert(file.clone());
            let text = serde_json::to_string_pretty(&fx).unwrap() + "\n";
            let path = dir.join(&file);
            if bless {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&path, &text).unwrap();
            } else if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                stale.push(file);
            }
        }
    }
    let present: BTreeSet<String> = std::fs::read_dir(&dir)
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    let extra: Vec<_> = present.difference(&expected).collect();
    assert!(extra.is_empty(), "fixtures without an example: {extra:?}");
    assert!(stale.is_empty(), "stale fixtures (run with PAGURO_BLESS=1): {stale:?}");
}

#[test]
fn every_method_has_a_cli_command() {
    let s = schema();
    for (name, d) in s["methods"].as_object().unwrap() {
        let argv: Vec<&str> = std::iter::once("paguro")
            .chain(d["cli_example"].as_array().unwrap_or_else(|| panic!("{name}: cli_example")).iter().filter_map(Value::as_str))
            .collect();
        let cli = paguro_win::cli::Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{name}: {argv:?}: {e}"));
        let (m, _) = paguro_win::cli::request(&cli.command)
            .unwrap_or_else(|e| panic!("{name}: {}", e.message))
            .unwrap_or_else(|| panic!("{name}: direct-only"));
        assert_eq!(m, name, "{argv:?}");
    }
}

#[test]
fn the_validator_refuses() {
    let s = schema();
    let v = V { defs: s["$defs"].as_object().unwrap() };
    let bad = [
        json!({ "id": "tpm_pin", "offered": "yes", "recommended": true, "reason": "" }),
        json!({ "id": "tpm_pin", "offered": true, "recommended": true }),
        json!({ "id": "sometimes", "offered": true, "recommended": true, "reason": "" }),
    ];
    for b in bad {
        let mut e = Vec::new();
        v.check(&json!({ "$ref": "#/$defs/ProtectionOffer" }), &b, "x", &mut e);
        assert!(!e.is_empty(), "{b}");
    }
    let mut e = Vec::new();
    v.check(&json!({ "$ref": "#/$defs/NameParams" }), &json!({ "name": "a", "other": 1 }), "x", &mut e);
    assert!(!e.is_empty());
    let mut e = Vec::new();
    v.check(&json!({ "$ref": "#/$defs/Distribution" }), &json!({ "name": "a", "kind": "image", "default": true, "exists": true, "bootable": true, "size": null }), "x", &mut e);
    assert!(e.is_empty(), "{e:?}");
}
