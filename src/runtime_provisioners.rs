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
use crate::policy::Provisioner;

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
            jwk_dir.join("grafhome-user-login.pub.json"),
            r#"{"kid":"user-login-kid","kty":"EC"}"#,
        )
        .unwrap();
        fs::write(
            jwk_dir.join("grafhome-user-login.priv.json"),
            "{\n  \"protected\": \"encrypted-user-login\"\n}\n",
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
        assert_eq!(bootstrap["claims"]["defaultHostSSHCertDuration"], "720h");
        let user_login = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-user-login")
            .unwrap();
        assert_eq!(user_login["key"]["kid"], "user-login-kid");
        assert!(
            user_login["encryptedKey"]
                .as_str()
                .unwrap()
                .contains("encrypted-user-login")
        );
        assert_eq!(user_login["claims"]["defaultUserSSHCertDuration"], "16h");
        assert!(
            provisioners
                .iter()
                .any(|item| item["name"] == "grafhome-host-renew")
        );
        assert!(
            provisioners
                .iter()
                .any(|item| item["name"] == "grafhome-x509-ca-proxy")
        );
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

        assert!(error.to_string().contains("grafhome-user-login.pub.json"));
    }
}
