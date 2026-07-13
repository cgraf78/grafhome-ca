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

use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::model::SiteModel;
use crate::policy::{Provisioner, step_max_ttl};

const USER_CLIENT_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome user/client-host provisioner" }}"#;
const HOST_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome host provisioner" }}"#;

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

/// Add one constrained per-user/per-host JWK provisioner to an existing CA config.
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
    let provisioners = config
        .pointer_mut("/authority/provisioners")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: "expected provisioners array".to_owned(),
        })?;

    if let Some(existing) = provisioners
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
    {
        if existing.get("key") == Some(&key) {
            return serde_json::to_string_pretty(&config).map_err(|source| Error::Json {
                path: ca_json.to_path_buf(),
                source,
            });
        }
        return Err(Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!("provisioner {name} already exists with a different public key"),
        });
    }

    provisioners.push(json!({
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
    }));

    serde_json::to_string_pretty(&config).map_err(|source| Error::Json {
        path: ca_json.to_path_buf(),
        source,
    })
}

/// Add one constrained per-host JWK provisioner to an existing CA config.
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

    if let Some(existing) = provisioners
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
    {
        if existing.get("key") == Some(&key) {
            return serialize_config(config, ca_json);
        }
        return Err(Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!("provisioner {name} already exists with a different public key"),
        });
    }

    provisioners.push(json!({
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
    }));

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
