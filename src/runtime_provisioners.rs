//! Materialize runtime-only Smallstep JWK provisioners.
//!
//! The normal renderer cannot include encrypted JWK private material because the
//! public repository must stay secret-free. During first bootstrap, `step ca
//! init` creates the host-bootstrap JWK object offline, and operators generate
//! any additional JWK keypairs with `step crypto jwk create`. This module owns
//! the deterministic merge from those runtime inputs into the rendered
//! placeholder-bearing `ca.json`.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::enrollment::{parse_host_provisioner_name, parse_user_provisioner_name};
use crate::error::{Error, Result};
use crate::model::SiteModel;
use crate::policy::{Provisioner, step_max_ttl};

const USER_CLIENT_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome user/client-host provisioner" }}"#;
const HOST_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome host provisioner" }}"#;

/// Result of reconciling managed Smallstep claims against policy.
#[derive(Debug, Eq, PartialEq)]
pub struct ClaimsReconciliation {
    /// Updated serialized CA configuration.
    pub config: String,
    /// Provisioner names whose managed claims changed.
    pub updated: Vec<String>,
}

/// Reconcile duration claims for every live Grafhome provisioner.
pub fn reconcile_claims(
    model: &SiteModel,
    ca_json: impl AsRef<Path>,
) -> Result<ClaimsReconciliation> {
    let ca_json = ca_json.as_ref();
    let mut config = read_json(ca_json)?;
    let user = active_provisioner(model, "user_enrollment")?;
    let host = active_provisioner(model, "host_bootstrap")?;
    let proxy = active_provisioner(model, "proxy_x509")?;
    let provisioners = provisioners_mut(&mut config, ca_json)?;
    let mut updated = Vec::new();

    for item in provisioners {
        let Some(name) = item.get("name").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        let desired = if name == user.name || parse_user_provisioner_name(&name).is_some() {
            user_claims(user)
        } else if name == host.name || parse_host_provisioner_name(&name).is_some() {
            host_claims(host)
        } else if name == proxy.name {
            proxy_claims(proxy)
        } else {
            continue;
        };
        let object = item.as_object_mut().ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!("provisioner {name} must be an object"),
        })?;
        let claims = object
            .entry("claims")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| Error::Validation {
                field: format!("{}:authority.provisioners", ca_json.display()),
                message: format!("provisioner {name} claims must be an object"),
            })?;
        if reconcile_object(claims, desired) {
            updated.push(name);
        }
    }

    Ok(ClaimsReconciliation {
        config: serialize_config(config, ca_json)?,
        updated,
    })
}

fn active_provisioner<'a>(model: &'a SiteModel, role: &str) -> Result<&'a Provisioner> {
    model
        .policy
        .provisioners
        .iter()
        .find(|provisioner| provisioner.role == role && provisioner.status == "active")
        .ok_or_else(|| Error::Validation {
            field: format!("policy/provisioners.toml:{role}"),
            message: "missing active provisioner".to_owned(),
        })
}

fn user_claims(provisioner: &Provisioner) -> Map<String, Value> {
    Map::from_iter([
        (
            "defaultUserSSHCertDuration".to_owned(),
            Value::String(provisioner.default_ttl.clone()),
        ),
        (
            "maxUserSSHCertDuration".to_owned(),
            Value::String(step_max_ttl(&provisioner.max_ttl).to_owned()),
        ),
        ("enableSSHCA".to_owned(), Value::Bool(true)),
    ])
}

fn host_claims(provisioner: &Provisioner) -> Map<String, Value> {
    Map::from_iter([
        (
            "defaultHostSSHCertDuration".to_owned(),
            Value::String(provisioner.default_ttl.clone()),
        ),
        (
            "maxHostSSHCertDuration".to_owned(),
            Value::String(step_max_ttl(&provisioner.max_ttl).to_owned()),
        ),
        ("enableSSHCA".to_owned(), Value::Bool(true)),
    ])
}

fn proxy_claims(provisioner: &Provisioner) -> Map<String, Value> {
    Map::from_iter([
        (
            "defaultTLSCertDuration".to_owned(),
            Value::String(provisioner.default_ttl.clone()),
        ),
        (
            "maxTLSCertDuration".to_owned(),
            Value::String(step_max_ttl(&provisioner.max_ttl).to_owned()),
        ),
    ])
}

fn reconcile_object(current: &mut Map<String, Value>, desired: Map<String, Value>) -> bool {
    let mut changed = false;
    for (key, value) in desired {
        if current.get(&key) != Some(&value) {
            current.insert(key, value);
            changed = true;
        }
    }
    changed
}

/// Install the exact constrained state for one Grafhome-owned scoped provisioner.
fn upsert_scoped_provisioner(
    provisioners: &mut Vec<Value>,
    desired: Value,
    ca_json: &Path,
) -> Result<()> {
    let name = desired
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: "desired scoped provisioner must have a string name".to_owned(),
        })?
        .to_owned();
    let matching = provisioners
        .iter()
        .enumerate()
        .filter(|(_, item)| item.get("name").and_then(Value::as_str) == Some(&name))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    let index = match matching.as_slice() {
        [] => {
            provisioners.push(desired);
            return Ok(());
        }
        [index] => *index,
        _ => {
            return Err(Error::Validation {
                field: format!("{}:authority.provisioners", ca_json.display()),
                message: format!("provisioner {name} appears more than once"),
            });
        }
    };
    let existing = &mut provisioners[index];

    if existing.get("key") != desired.get("key") {
        return Err(Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!("provisioner {name} already exists with a different public key"),
        });
    }

    // Public-key equality proves this is the same scoped identity. Replace the full object so
    // stale claims, encrypted signing keys, webhooks, or templates cannot broaden its authority.
    *existing = desired;
    Ok(())
}

/// Replace rendered JWK placeholders with runtime-generated provisioner objects.
pub fn materialize(
    model: &SiteModel,
    live_ca_json: impl AsRef<Path>,
    staged_ca_json: impl AsRef<Path>,
    jwk_dir: impl AsRef<Path>,
) -> Result<String> {
    let live_ca_json = live_ca_json.as_ref();
    let staged_ca_json = staged_ca_json.as_ref();
    let jwk_dir = jwk_dir.as_ref();
    let live = read_json(live_ca_json)?;
    let mut staged = read_json(staged_ca_json)?;
    let live_jwks = live_jwk_provisioners(&live, live_ca_json)?;
    let active_jwks = active_jwk_provisioners(model);
    let mut replacements = BTreeMap::new();

    for provisioner in &active_jwks {
        let object = if let Some(live) = live_jwks.get(&provisioner.name) {
            runtime_jwk_from_live(model, provisioner, live)?
        } else {
            runtime_jwk_from_files(model, provisioner, jwk_dir)?
        };
        replacements.insert(
            crate::render::provisioner_placeholder(&provisioner.name),
            object,
        );
    }

    let provisioners = staged
        .pointer_mut("/authority/provisioners")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", staged_ca_json.display()),
            message: "expected provisioners array".to_owned(),
        })?;

    for item in provisioners.iter_mut() {
        let Some(placeholder) = item.as_str() else {
            continue;
        };
        if !placeholder.starts_with("RUNTIME_SECRET_PLACEHOLDER:") {
            continue;
        }
        let replacement = replacements
            .remove(placeholder)
            .ok_or_else(|| Error::Validation {
                field: format!("{}:authority.provisioners", staged_ca_json.display()),
                message: format!("unknown runtime placeholder {placeholder}"),
            })?;
        *item = replacement;
    }

    if let Some((placeholder, _)) = replacements.into_iter().next() {
        return Err(Error::Validation {
            field: format!("{}:authority.provisioners", staged_ca_json.display()),
            message: format!("missing runtime placeholder {placeholder}"),
        });
    }

    serde_json::to_string_pretty(&staged).map_err(|source| Error::Json {
        path: staged_ca_json.to_path_buf(),
        source,
    })
}

/// Add or reconcile one constrained user/client-host JWK provisioner.
///
/// An existing provisioner with the same name and key is replaced with exact managed state.
/// Different keys or duplicate names are rejected without changing the serialized config.
pub fn add_user_client(
    ca_json: impl AsRef<Path>,
    public_key: impl AsRef<Path>,
    name: &str,
    template_file: &str,
    default_ttl: &str,
    max_ttl: &str,
) -> Result<String> {
    let ca_json = ca_json.as_ref();
    let public_key = public_key.as_ref();
    let mut config = read_json(ca_json)?;
    let key = read_public_jwk(public_key)?;
    let template = read_text(Path::new(template_file))?;
    let provisioners = provisioners_mut(&mut config, ca_json)?;

    let desired = json!({
        "type": "JWK",
        "name": name,
        "key": key,
        "claims": {
            "defaultUserSSHCertDuration": default_ttl,
            "maxUserSSHCertDuration": step_max_ttl(max_ttl),
            "enableSSHCA": true,
        },
        "options": {
            "x509": {
                "template": USER_CLIENT_X509_DENY_TEMPLATE,
            },
            "ssh": {
                "template": template,
            },
        },
    });
    upsert_scoped_provisioner(provisioners, desired, ca_json)?;

    serialize_config(config, ca_json)
}

/// Add or reconcile one constrained host JWK provisioner.
///
/// An existing provisioner with the same name and key is replaced with exact managed state.
/// Different keys or duplicate names are rejected without changing the serialized config.
pub fn add_host(
    ca_json: impl AsRef<Path>,
    public_key: impl AsRef<Path>,
    name: &str,
    template_file: &str,
    default_ttl: &str,
    max_ttl: &str,
) -> Result<String> {
    let ca_json = ca_json.as_ref();
    let public_key = public_key.as_ref();
    let mut config = read_json(ca_json)?;
    let key = read_public_jwk(public_key)?;
    let template = read_text(Path::new(template_file))?;
    let provisioners = provisioners_mut(&mut config, ca_json)?;
    // A retained SSHPOP provisioner would bypass host-scoped revocation.
    provisioners.retain(|item| item.get("type").and_then(Value::as_str) != Some("SSHPOP"));

    let desired = json!({
        "type": "JWK",
        "name": name,
        "key": key,
        "claims": {
            "defaultHostSSHCertDuration": default_ttl,
            "maxHostSSHCertDuration": step_max_ttl(max_ttl),
            "enableSSHCA": true,
        },
        "options": {
            "x509": { "template": HOST_X509_DENY_TEMPLATE },
            "ssh": { "template": template },
        },
    });
    upsert_scoped_provisioner(provisioners, desired, ca_json)?;

    serialize_config(config, ca_json)
}

/// Remove one exact scoped JWK provisioner from an existing CA config.
pub fn remove_exact(ca_json: impl AsRef<Path>, name: &str) -> Result<(String, Vec<String>)> {
    remove_matching(ca_json, |item_name, _| item_name == Some(name))
}

/// Remove every live provisioner belonging to one user.
pub fn remove_user(ca_json: impl AsRef<Path>, prefix: &str) -> Result<(String, Vec<String>)> {
    remove_matching(ca_json, |item_name, _| {
        item_name.is_some_and(|name| name.starts_with(prefix))
    })
}

/// Remove a host issuer, all user issuers on that host, and legacy SSHPOP.
pub fn remove_host(
    ca_json: impl AsRef<Path>,
    host_name: &str,
    user_host_suffix: &str,
) -> Result<(String, Vec<String>)> {
    remove_matching(ca_json, |item_name, item_type| {
        item_name == Some(host_name)
            || item_name.is_some_and(|name| {
                name.starts_with("grafhome-user-") && name.ends_with(user_host_suffix)
            })
            || item_type == Some("SSHPOP")
    })
}

/// Read the configured provisioner names from live CA state.
pub fn provisioner_names(ca_json: impl AsRef<Path>) -> Result<Vec<String>> {
    let ca_json = ca_json.as_ref();
    let config = read_json(ca_json)?;
    let provisioners = config
        .pointer("/authority/provisioners")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: "expected provisioners array".to_owned(),
        })?;
    Ok(provisioners
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect())
}

fn remove_matching(
    ca_json: impl AsRef<Path>,
    mut matches: impl FnMut(Option<&str>, Option<&str>) -> bool,
) -> Result<(String, Vec<String>)> {
    let ca_json = ca_json.as_ref();
    let mut config = read_json(ca_json)?;
    let provisioners = provisioners_mut(&mut config, ca_json)?;
    let mut removed = Vec::new();
    provisioners.retain(|item| {
        let name = item.get("name").and_then(Value::as_str);
        let item_type = item.get("type").and_then(Value::as_str);
        if matches(name, item_type) {
            if let Some(name) = name {
                removed.push(name.to_owned());
            }
            false
        } else {
            true
        }
    });
    let text = serialize_config(config, ca_json)?;
    Ok((text, removed))
}

fn provisioners_mut<'a>(config: &'a mut Value, path: &Path) -> Result<&'a mut Vec<Value>> {
    config
        .pointer_mut("/authority/provisioners")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", path.display()),
            message: "expected provisioners array".to_owned(),
        })
}

fn serialize_config(config: Value, path: &Path) -> Result<String> {
    serde_json::to_string_pretty(&config).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
    serde_json::from_str(&text).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|source| Error::io(path, source))
}

fn read_public_jwk(path: &Path) -> Result<Value> {
    let key = read_json(path)?;
    let object = key.as_object().ok_or_else(|| Error::Validation {
        field: path.display().to_string(),
        message: "public JWK must be a JSON object".to_owned(),
    })?;
    if object.contains_key("d") {
        return Err(Error::Validation {
            field: path.display().to_string(),
            message: "public JWK must not contain private key material".to_owned(),
        });
    }
    Ok(key)
}

fn active_jwk_provisioners(model: &SiteModel) -> Vec<&Provisioner> {
    model
        .policy
        .provisioners
        .iter()
        .filter(|entry| entry.status == "active" && entry.r#type == "JWK")
        .collect()
}

fn live_jwk_provisioners(live: &Value, path: &Path) -> Result<BTreeMap<String, Value>> {
    let provisioners = live
        .pointer("/authority/provisioners")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", path.display()),
            message: "expected provisioners array".to_owned(),
        })?;
    let mut by_name = BTreeMap::new();
    for item in provisioners {
        if item.get("type").and_then(Value::as_str) != Some("JWK") {
            continue;
        }
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Validation {
                field: format!("{}:authority.provisioners[].name", path.display()),
                message: "JWK provisioner is missing a name".to_owned(),
            })?;
        by_name.insert(name.to_owned(), item.clone());
    }
    Ok(by_name)
}

fn runtime_jwk_from_live(
    model: &SiteModel,
    provisioner: &Provisioner,
    live: &Value,
) -> Result<Value> {
    let mut object = live.clone();
    require_object_field(&object, "key", &provisioner.name)?;
    require_object_field(&object, "encryptedKey", &provisioner.name)?;
    object["type"] = json!("JWK");
    object["name"] = json!(provisioner.name);
    object["claims"] = crate::render::active_provisioner_claims(model, &provisioner.name)?;
    Ok(object)
}

fn runtime_jwk_from_files(
    model: &SiteModel,
    provisioner: &Provisioner,
    jwk_dir: &Path,
) -> Result<Value> {
    let public_path = jwk_dir.join(format!("{}.pub.json", provisioner.name));
    let private_path = jwk_dir.join(format!("{}.priv.json", provisioner.name));
    let public = read_json(&public_path)?;
    let encrypted = read_text(&private_path)?;
    Ok(json!({
        "type": "JWK",
        "name": provisioner.name,
        "key": public,
        "encryptedKey": encrypted.trim_end_matches('\n'),
        "claims": crate::render::active_provisioner_claims(model, &provisioner.name)?,
    }))
}

fn require_object_field(object: &Value, field: &str, name: &str) -> Result<()> {
    if object.get(field).is_some() {
        Ok(())
    } else {
        Err(Error::Validation {
            field: format!("live ca.json provisioner {name}.{field}"),
            message: "missing runtime JWK material".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn reconciles_live_managed_claims_without_replacing_other_state() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let ca_json = dir.path().join("ca.json");
        fs::write(
            &ca_json,
            serde_json::to_vec_pretty(&json!({
                "authority": {
                    "provisioners": [
                        {
                            "type": "JWK",
                            "name": "grafhome-user-enrollment",
                            "key": {"kid": "static-user"},
                            "encryptedKey": "preserve-static-secret",
                            "claims": {
                                "defaultUserSSHCertDuration": "12h",
                                "maxUserSSHCertDuration": "168h",
                                "disableRenewal": true
                            }
                        },
                        {
                            "type": "JWK",
                            "name": crate::enrollment::user_provisioner_name("alice", "ca-host"),
                            "key": {"kid": "client"},
                            "options": {"ssh": {"templateFile": "preserve.tpl"}},
                            "claims": {"maxUserSSHCertDuration": "168h"}
                        },
                        {
                            "type": "JWK",
                            "name": crate::enrollment::host_provisioner_name("proxy-host"),
                            "key": {"kid": "host"},
                            "claims": {"maxHostSSHCertDuration": "24h"}
                        },
                        {
                            "type": "ACME",
                            "name": "grafhome-x509-ca-proxy",
                            "claims": {"maxTLSCertDuration": "24h"}
                        },
                        {
                            "type": "JWK",
                            "name": "operator-owned",
                            "claims": {"maxUserSSHCertDuration": "1h"}
                        }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = reconcile_claims(&model, &ca_json).unwrap();
        assert_eq!(result.updated.len(), 4);
        let value: Value = serde_json::from_str(&result.config).unwrap();
        let provisioners = value["authority"]["provisioners"].as_array().unwrap();
        let by_name = provisioners
            .iter()
            .map(|item| (item["name"].as_str().unwrap(), item))
            .collect::<BTreeMap<_, _>>();
        let user = by_name["grafhome-user-enrollment"];
        assert_eq!(user["key"]["kid"], "static-user");
        assert_eq!(user["encryptedKey"], "preserve-static-secret");
        assert_eq!(user["claims"]["disableRenewal"], true);
        assert_eq!(user["claims"]["defaultUserSSHCertDuration"], "24h");
        assert_eq!(user["claims"]["maxUserSSHCertDuration"], "2562047h");
        let client_name = crate::enrollment::user_provisioner_name("alice", "ca-host");
        let client = by_name[client_name.as_str()];
        assert_eq!(client["options"]["ssh"]["templateFile"], "preserve.tpl");
        assert_eq!(client["claims"]["maxUserSSHCertDuration"], "2562047h");
        let host_name = crate::enrollment::host_provisioner_name("proxy-host");
        assert_eq!(
            by_name[host_name.as_str()]["claims"]["maxHostSSHCertDuration"],
            "720h"
        );
        assert_eq!(
            by_name["grafhome-x509-ca-proxy"]["claims"]["maxTLSCertDuration"],
            "720h"
        );
        assert_eq!(
            by_name["operator-owned"]["claims"]["maxUserSSHCertDuration"],
            "1h"
        );

        fs::write(&ca_json, result.config).unwrap();
        assert!(
            reconcile_claims(&model, &ca_json)
                .unwrap()
                .updated
                .is_empty()
        );
    }

    #[test]
    fn materializes_runtime_jwks_without_admin_api_inputs() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let staged_path = dir.path().join("staged-ca.json");
        fs::write(
            &staged_path,
            crate::render::render(&model)
                .unwrap()
                .into_iter()
                .find(|file| file.path.ends_with("step/config/ca.json"))
                .unwrap()
                .content,
        )
        .unwrap();
        let live_path = dir.path().join("live-ca.json");
        fs::write(
            &live_path,
            r#"{
              "authority": {
                "provisioners": [
                  {
                    "type": "JWK",
                    "name": "grafhome-host-bootstrap",
                    "key": {"kid": "bootstrap-kid"},
                    "encryptedKey": "encrypted-bootstrap",
                    "claims": {"enableSSHCA": true}
                  }
                ]
              }
            }"#,
        )
        .unwrap();
        let jwk_dir = dir.path().join("provisioners");
        fs::create_dir(&jwk_dir).unwrap();
        fs::write(
            jwk_dir.join("grafhome-user-enrollment.pub.json"),
            r#"{"kid":"user-enrollment-kid","kty":"EC"}"#,
        )
        .unwrap();
        fs::write(
            jwk_dir.join("grafhome-user-enrollment.priv.json"),
            "{\n  \"protected\": \"encrypted-user-enrollment\"\n}\n",
        )
        .unwrap();

        let text = materialize(&model, &live_path, &staged_path, &jwk_dir).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let provisioners = value["authority"]["provisioners"].as_array().unwrap();

        assert!(!text.contains("RUNTIME_SECRET_PLACEHOLDER"));
        let bootstrap = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-host-bootstrap")
            .unwrap();
        assert_eq!(bootstrap["key"]["kid"], "bootstrap-kid");
        assert_eq!(bootstrap["encryptedKey"], "encrypted-bootstrap");
        assert_eq!(bootstrap["claims"]["defaultHostSSHCertDuration"], "168h");
        let user_enrollment = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-user-enrollment")
            .unwrap();
        assert_eq!(user_enrollment["key"]["kid"], "user-enrollment-kid");
        assert!(
            user_enrollment["encryptedKey"]
                .as_str()
                .unwrap()
                .contains("encrypted-user-enrollment")
        );
        assert_eq!(
            user_enrollment["claims"]["defaultUserSSHCertDuration"],
            "24h"
        );
        assert!(!provisioners.iter().any(|item| item["type"] == "SSHPOP"));
        assert!(
            provisioners
                .iter()
                .any(|item| item["name"] == "grafhome-x509-ca-proxy")
        );
    }

    #[test]
    fn adds_user_client_provisioner_without_host_ssh_claims() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(&public_key, r#"{"kid":"client-kid","kty":"EC"}"#).unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, r#"{"type":"user","principals":["alice"]}"#).unwrap();

        let text = add_user_client(
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
            "24h",
            "unlimited",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let provisioner = &value["authority"]["provisioners"][0];

        assert_eq!(provisioner["name"], "grafhome-user-alice-ca-host");
        assert_eq!(provisioner["key"]["kid"], "client-kid");
        assert_eq!(provisioner["claims"]["defaultUserSSHCertDuration"], "24h");
        assert_eq!(
            provisioner["claims"]["maxUserSSHCertDuration"],
            crate::policy::STEP_EFFECTIVE_UNLIMITED_TTL
        );
        assert_eq!(provisioner["claims"]["enableSSHCA"], true);
        assert!(provisioner["claims"]["defaultHostSSHCertDuration"].is_null());
        assert!(provisioner["claims"]["maxHostSSHCertDuration"].is_null());
        assert_eq!(
            provisioner["options"]["x509"]["template"],
            USER_CLIENT_X509_DENY_TEMPLATE
        );
        assert_eq!(
            provisioner["options"]["ssh"]["template"],
            r#"{"type":"user","principals":["alice"]}"#
        );
    }

    #[test]
    fn replaces_existing_user_client_provisioner_with_same_key() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        fs::write(
            &ca_json,
            serde_json::to_vec_pretty(&json!({
                "authority": {
                    "provisioners": [
                        {"type": "ACME", "name": "preserve-before", "claims": {"x": 1}},
                        {
                            "type": "JWK",
                            "name": "grafhome-user-alice-ca-host",
                            "key": {"kid": "client-kid", "kty": "EC"},
                            "claims": {
                                "defaultUserSSHCertDuration": "12h",
                                "maxUserSSHCertDuration": "168h",
                                "enableSSHCA": false,
                                "disableRenewal": true
                            },
                            "options": {
                                "x509": {"template": "stale-x509", "webhooks": ["remove"]},
                                "ssh": {"template": "stale-ssh", "templateFile": "remove.tpl"}
                            },
                            "encryptedKey": "remove-step-state"
                        },
                        {"type": "OIDC", "name": "preserve-after", "options": {"x": 2}}
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(&public_key, r#"{"kid":"client-kid","kty":"EC"}"#).unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, r#"{"type":"user","principals":["alice"]}"#).unwrap();

        let text = add_user_client(
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
            "24h",
            "unlimited",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let provisioners = value["authority"]["provisioners"].as_array().unwrap();
        let provisioner = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-user-alice-ca-host")
            .unwrap();

        assert_eq!(provisioners.len(), 3);
        assert_eq!(
            provisioners[0],
            json!({"type": "ACME", "name": "preserve-before", "claims": {"x": 1}})
        );
        assert_eq!(
            provisioners[2],
            json!({"type": "OIDC", "name": "preserve-after", "options": {"x": 2}})
        );
        assert_eq!(provisioner["claims"]["defaultUserSSHCertDuration"], "24h");
        assert_eq!(
            provisioner["claims"]["maxUserSSHCertDuration"],
            crate::policy::STEP_EFFECTIVE_UNLIMITED_TTL
        );
        assert_eq!(provisioner["claims"]["enableSSHCA"], true);
        assert!(
            provisioner["claims"]
                .as_object()
                .unwrap()
                .get("disableRenewal")
                .is_none()
        );
        assert_eq!(
            provisioner["options"]["x509"]["template"],
            USER_CLIENT_X509_DENY_TEMPLATE
        );
        assert!(
            provisioner["options"]["x509"]
                .as_object()
                .unwrap()
                .get("webhooks")
                .is_none()
        );
        assert_eq!(
            provisioner["options"]["ssh"]["template"],
            r#"{"type":"user","principals":["alice"]}"#
        );
        assert!(
            provisioner["options"]["ssh"]
                .as_object()
                .unwrap()
                .get("templateFile")
                .is_none()
        );
        assert!(
            provisioner
                .as_object()
                .unwrap()
                .get("encryptedKey")
                .is_none()
        );

        fs::write(&ca_json, &text).unwrap();
        assert_eq!(
            add_user_client(
                &ca_json,
                &public_key,
                "grafhome-user-alice-ca-host",
                template.to_str().unwrap(),
                "24h",
                "unlimited",
            )
            .unwrap(),
            text
        );
    }

    #[test]
    fn adds_host_provisioner_without_user_ssh_claims() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        fs::write(
            &ca_json,
            r#"{"authority":{"provisioners":[{"type":"SSHPOP","name":"legacy"}]}}"#,
        )
        .unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(&public_key, r#"{"kid":"host-kid","kty":"EC"}"#).unwrap();
        let template = dir.path().join("host.tpl");
        fs::write(&template, r#"{"type":"host","principals":["edge"]}"#).unwrap();

        let text = add_host(
            &ca_json,
            &public_key,
            "grafhome-host-edge",
            template.to_str().unwrap(),
            "168h",
            "720h",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let provisioner = &value["authority"]["provisioners"][0];

        assert_eq!(
            value["authority"]["provisioners"].as_array().unwrap().len(),
            1
        );
        assert_eq!(provisioner["name"], "grafhome-host-edge");
        assert_eq!(provisioner["claims"]["defaultHostSSHCertDuration"], "168h");
        assert_eq!(provisioner["claims"]["maxHostSSHCertDuration"], "720h");
        assert!(provisioner["claims"]["defaultUserSSHCertDuration"].is_null());
        assert_eq!(
            provisioner["options"]["x509"]["template"],
            HOST_X509_DENY_TEMPLATE
        );
    }

    #[test]
    fn replaces_existing_host_provisioner_with_same_key() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        fs::write(
            &ca_json,
            serde_json::to_vec_pretty(&json!({
                "authority": {
                    "provisioners": [{
                        "type": "JWK",
                        "name": "grafhome-host-edge",
                        "key": {"kid": "host-kid", "kty": "EC"},
                        "claims": {
                            "defaultHostSSHCertDuration": "24h",
                            "maxHostSSHCertDuration": "168h",
                            "enableSSHCA": false,
                            "disableRenewal": true
                        },
                        "options": {
                            "x509": {"template": "stale-x509"},
                            "ssh": {"template": "stale-ssh", "webhooks": ["preserve"]}
                        }
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(&public_key, r#"{"kid":"host-kid","kty":"EC"}"#).unwrap();
        let template = dir.path().join("host.tpl");
        fs::write(&template, r#"{"type":"host","principals":["edge"]}"#).unwrap();

        let text = add_host(
            &ca_json,
            &public_key,
            "grafhome-host-edge",
            template.to_str().unwrap(),
            "168h",
            "720h",
        )
        .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let provisioner = &value["authority"]["provisioners"][0];

        assert_eq!(provisioner["claims"]["defaultHostSSHCertDuration"], "168h");
        assert_eq!(provisioner["claims"]["maxHostSSHCertDuration"], "720h");
        assert_eq!(provisioner["claims"]["enableSSHCA"], true);
        assert!(
            provisioner["claims"]
                .as_object()
                .unwrap()
                .get("disableRenewal")
                .is_none()
        );
        assert_eq!(
            provisioner["options"]["x509"]["template"],
            HOST_X509_DENY_TEMPLATE
        );
        assert_eq!(
            provisioner["options"]["ssh"]["template"],
            r#"{"type":"host","principals":["edge"]}"#
        );
        assert!(
            provisioner["options"]["ssh"]
                .as_object()
                .unwrap()
                .get("webhooks")
                .is_none()
        );
    }

    #[test]
    fn rejects_existing_user_client_provisioner_with_different_key() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-user-alice-ca-host","key":{"kid":"other","kty":"EC"}}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(&public_key, r#"{"kid":"client-kid","kty":"EC"}"#).unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, "user-template").unwrap();

        let error = add_user_client(
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
            "24h",
            "unlimited",
        )
        .unwrap_err();

        assert!(error.to_string().contains("different public key"));
        assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
    }

    #[test]
    fn rejects_existing_host_provisioner_with_different_key() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-host-edge","key":{"kid":"other","kty":"EC"}}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(&public_key, r#"{"kid":"host-kid","kty":"EC"}"#).unwrap();
        let template = dir.path().join("host.tpl");
        fs::write(&template, "host-template").unwrap();

        let error = add_host(
            &ca_json,
            &public_key,
            "grafhome-host-edge",
            template.to_str().unwrap(),
            "168h",
            "720h",
        )
        .unwrap_err();

        assert!(error.to_string().contains("different public key"));
        assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
    }

    #[test]
    fn rejects_duplicate_scoped_provisioner_names() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-user-alice-ca-host","key":{"kid":"client-kid","kty":"EC"}},{"type":"JWK","name":"grafhome-user-alice-ca-host","key":{"kid":"client-kid","kty":"EC"}}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(&public_key, r#"{"kid":"client-kid","kty":"EC"}"#).unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, "user-template").unwrap();

        let error = add_user_client(
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
            "24h",
            "unlimited",
        )
        .unwrap_err();

        assert!(error.to_string().contains("appears more than once"));
        assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
    }

    #[test]
    fn rejects_private_jwk_for_user_client_public_key() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","d":"secret"}"#,
        )
        .unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, r#"{"type":"user","principals":["alice"]}"#).unwrap();

        let error = add_user_client(
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
            "24h",
            "168h",
        )
        .unwrap_err();

        assert!(error.to_string().contains("must not contain private key"));
    }

    #[test]
    fn rejects_missing_runtime_jwk_files() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let staged_path = dir.path().join("staged-ca.json");
        fs::write(
            &staged_path,
            crate::render::render(&model)
                .unwrap()
                .into_iter()
                .find(|file| file.path.ends_with("step/config/ca.json"))
                .unwrap()
                .content,
        )
        .unwrap();
        let live_path = dir.path().join("live-ca.json");
        fs::write(
            &live_path,
            r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-host-bootstrap","key":{},"encryptedKey":"x"}]}}"#,
        )
        .unwrap();
        let jwk_dir = dir.path().join("provisioners");
        fs::create_dir(&jwk_dir).unwrap();

        let error = materialize(&model, &live_path, &staged_path, &jwk_dir).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("grafhome-user-enrollment.pub.json")
        );
    }
}
