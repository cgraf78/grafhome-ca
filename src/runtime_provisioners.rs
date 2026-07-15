//! Materialize runtime-only Smallstep JWK provisioners.
//!
//! The normal renderer cannot include runtime-generated JWK public keys. During
//! first bootstrap, `step ca init` creates the host-bootstrap JWK object, and
//! operators generate any additional JWK keypairs with `step crypto jwk
//! create`. This module owns the deterministic merge from those public inputs
//! into rendered `ca.json` while preserving existing device-bound renewal
//! provisioners. Encrypted private keys remain server-local files.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Map, Value, json};

use crate::enrollment::{parse_host_provisioner_name, parse_user_provisioner_name};
use crate::error::{Error, Result};
use crate::model::SiteModel;
use crate::policy::{
    PROVISIONER_ROLE_HOST_BOOTSTRAP, PROVISIONER_ROLE_PROXY_X509, PROVISIONER_ROLE_USER_ENROLLMENT,
    Provisioner, ca_policy_field, step_max_ttl,
};

const USER_CLIENT_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome user renewal provisioner" }}"#;
const HOST_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome host renewal provisioner" }}"#;
const USER_ENROLLMENT_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome user enrollment provisioner" }}"#;
const HOST_BOOTSTRAP_X509_DENY_TEMPLATE: &str =
    r#"{{ fail "x509 issuance disabled for Grafhome host bootstrap provisioner" }}"#;
const USER_ENROLLMENT_SSH_TEMPLATE: &str = r#"{
  "type": "user",
  "keyId": {{ toJson .KeyID }},
  "principals": {{ toJson .Principals }},
  "criticalOptions": {{ toJson .CriticalOptions }},
  "extensions": {{ toJson .Extensions }}
}
"#;
const HOST_BOOTSTRAP_SSH_TEMPLATE: &str = r#"{
  "type": "host",
  "keyId": {{ toJson .KeyID }},
  "principals": {{ toJson .Principals }},
  "criticalOptions": {{ toJson .CriticalOptions }},
  "extensions": {{ toJson .Extensions }}
}
"#;

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
    let user = active_provisioner(model, PROVISIONER_ROLE_USER_ENROLLMENT)?;
    let host = active_provisioner(model, PROVISIONER_ROLE_HOST_BOOTSTRAP)?;
    let proxy = active_provisioner(model, PROVISIONER_ROLE_PROXY_X509)?;
    let provisioners = provisioners_mut(&mut config, ca_json)?;
    let mut updated = Vec::new();

    for item in provisioners {
        let Some(name) = item.get("name").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        let desired = if name == user.name {
            user_claims(user)
        } else if parse_user_provisioner_name(&name).is_some() {
            user_renewal_claims(model, user)
        } else if name == host.name {
            host_claims(host)
        } else if parse_host_provisioner_name(&name).is_some() {
            host_renewal_claims(model, host)
        } else if name == proxy.name {
            proxy_claims(proxy)
        } else {
            continue;
        };
        let claims_changed = reconcile_provisioner_claims(item, &name, desired, ca_json)?;
        let options_changed = if name == user.name {
            reconcile_enrollment_options(item, user, ca_json)?
        } else if name == host.name {
            reconcile_enrollment_options(item, host, ca_json)?
        } else {
            false
        };
        if claims_changed || options_changed {
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
            field: ca_policy_field("provisioners", role, "role"),
            message: "missing active provisioner".to_owned(),
        })
}

fn user_claims(provisioner: &Provisioner) -> Map<String, Value> {
    user_claims_for(&provisioner.default_ttl, &provisioner.max_ttl)
}

fn user_renewal_claims(model: &SiteModel, provisioner: &Provisioner) -> Map<String, Value> {
    user_claims_for(
        provisioner.renewal_default_ttl(),
        model.policy.renewal_max_ttl(provisioner),
    )
}

fn user_claims_for(default_ttl: &str, max_ttl: &str) -> Map<String, Value> {
    Map::from_iter([
        (
            "defaultUserSSHCertDuration".to_owned(),
            Value::String(default_ttl.to_owned()),
        ),
        (
            "maxUserSSHCertDuration".to_owned(),
            Value::String(step_max_ttl(max_ttl).to_owned()),
        ),
        ("enableSSHCA".to_owned(), Value::Bool(true)),
    ])
}

fn host_claims(provisioner: &Provisioner) -> Map<String, Value> {
    host_claims_for(&provisioner.default_ttl, &provisioner.max_ttl)
}

fn host_renewal_claims(model: &SiteModel, provisioner: &Provisioner) -> Map<String, Value> {
    host_claims_for(
        provisioner.renewal_default_ttl(),
        model.policy.renewal_max_ttl(provisioner),
    )
}

fn host_claims_for(default_ttl: &str, max_ttl: &str) -> Map<String, Value> {
    Map::from_iter([
        (
            "defaultHostSSHCertDuration".to_owned(),
            Value::String(default_ttl.to_owned()),
        ),
        (
            "maxHostSSHCertDuration".to_owned(),
            Value::String(step_max_ttl(max_ttl).to_owned()),
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

fn reconcile_provisioner_claims(
    provisioner: &mut Value,
    name: &str,
    desired: Map<String, Value>,
    ca_json: &Path,
) -> Result<bool> {
    let object = provisioner
        .as_object_mut()
        .ok_or_else(|| Error::Validation {
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
    Ok(reconcile_object(claims, desired))
}

/// Reconcile one required policy issuer without replacing its runtime key material.
fn reconcile_required_provisioner(
    provisioners: &mut [Value],
    provisioner: &Provisioner,
    desired: Map<String, Value>,
    ca_json: &Path,
) -> Result<()> {
    let matching = provisioners
        .iter()
        .enumerate()
        .filter(|(_, item)| item.get("name").and_then(Value::as_str) == Some(&provisioner.name))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let index = match matching.as_slice() {
        [index] => *index,
        [] => {
            return Err(Error::Validation {
                field: format!("{}:authority.provisioners", ca_json.display()),
                message: format!("required live provisioner {} is missing", provisioner.name),
            });
        }
        _ => {
            return Err(Error::Validation {
                field: format!("{}:authority.provisioners", ca_json.display()),
                message: format!("provisioner {} appears more than once", provisioner.name),
            });
        }
    };
    let live = &provisioners[index];
    if live.get("type").and_then(Value::as_str) != Some(&provisioner.r#type) {
        return Err(Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!(
                "provisioner {} must have type {}",
                provisioner.name, provisioner.r#type
            ),
        });
    }
    if live.get("key").and_then(Value::as_object).is_none() {
        return Err(Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!("provisioner {} key must be an object", provisioner.name),
        });
    }
    reconcile_provisioner_claims(
        &mut provisioners[index],
        &provisioner.name,
        desired,
        ca_json,
    )?;
    reconcile_enrollment_options(&mut provisioners[index], provisioner, ca_json)?;
    Ok(())
}

fn enrollment_options(provisioner: &Provisioner) -> Option<Value> {
    let (x509, ssh) = match provisioner.role.as_str() {
        PROVISIONER_ROLE_USER_ENROLLMENT => (
            USER_ENROLLMENT_X509_DENY_TEMPLATE,
            USER_ENROLLMENT_SSH_TEMPLATE,
        ),
        PROVISIONER_ROLE_HOST_BOOTSTRAP => (
            HOST_BOOTSTRAP_X509_DENY_TEMPLATE,
            HOST_BOOTSTRAP_SSH_TEMPLATE,
        ),
        _ => return None,
    };
    Some(json!({
        "x509": {"template": x509},
        "ssh": {"template": ssh},
    }))
}

fn reconcile_enrollment_options(
    live: &mut Value,
    provisioner: &Provisioner,
    ca_json: &Path,
) -> Result<bool> {
    let Some(options) = enrollment_options(provisioner) else {
        return Ok(false);
    };
    let object = live.as_object_mut().ok_or_else(|| Error::Validation {
        field: format!("{}:authority.provisioners", ca_json.display()),
        message: format!("provisioner {} must be an object", provisioner.name),
    })?;
    if object.get("options") == Some(&options) {
        Ok(false)
    } else {
        object.insert("options".to_owned(), options);
        Ok(true)
    }
}

/// Install the exact constrained state for one Grafhome-owned renewal provisioner.
fn upsert_renewal_provisioner(
    provisioners: &mut Vec<Value>,
    desired: Value,
    ca_json: &Path,
) -> Result<()> {
    let name = desired
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: "desired renewal provisioner must have a string name".to_owned(),
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

    // Public-key equality proves this is the same renewal identity. Replace the full object so
    // stale claims, encrypted signing keys, webhooks, or templates cannot broaden its authority.
    *existing = desired;
    Ok(())
}

fn user_client_provisioner(
    key: Value,
    name: &str,
    template: String,
    claims: Map<String, Value>,
) -> Value {
    json!({
        "type": "JWK",
        "name": name,
        "key": key,
        "claims": claims,
        "options": {
            "x509": {
                "template": USER_CLIENT_X509_DENY_TEMPLATE,
            },
            "ssh": {
                "template": template,
            },
        },
    })
}

fn host_provisioner(key: Value, name: &str, template: String, claims: Map<String, Value>) -> Value {
    json!({
        "type": "JWK",
        "name": name,
        "key": key,
        "claims": claims,
        "options": {
            "x509": { "template": HOST_X509_DENY_TEMPLATE },
            "ssh": { "template": template },
        },
    })
}

/// Validate enrollment credentials and replace rendered JWK placeholders.
pub fn materialize(
    model: &SiteModel,
    live_ca_json: impl AsRef<Path>,
    staged_ca_json: impl AsRef<Path>,
    jwk_dir: impl AsRef<Path>,
    step_bin: impl AsRef<Path>,
) -> Result<String> {
    let live_ca_json = live_ca_json.as_ref();
    let staged_ca_json = staged_ca_json.as_ref();
    let jwk_dir = jwk_dir.as_ref();
    let live = read_json(live_ca_json)?;
    let live_jwks = live_jwk_provisioners(&live, live_ca_json)?;
    for role in [
        PROVISIONER_ROLE_HOST_BOOTSTRAP,
        PROVISIONER_ROLE_USER_ENROLLMENT,
    ] {
        let provisioner = active_provisioner(model, role)?;
        let canonical_path = jwk_dir.join(format!("{}.pub.json", provisioner.name));
        let canonical;
        let expected = if let Some(live) = live_jwks.get(&provisioner.name) {
            live.get("key").ok_or_else(|| Error::Validation {
                field: format!("live enrollment provisioner {}.key", provisioner.name),
                message: "public JWK is missing".to_owned(),
            })?
        } else {
            canonical = read_public_jwk(&canonical_path)?;
            &canonical
        };
        validate_enrollment_provisioner_key_files(
            model,
            jwk_dir,
            &provisioner.name,
            expected,
            step_bin.as_ref(),
        )?;
    }
    merge_materialized(model, live_ca_json, staged_ca_json, jwk_dir)
}

fn merge_materialized(
    model: &SiteModel,
    live_ca_json: &Path,
    staged_ca_json: &Path,
    jwk_dir: &Path,
) -> Result<String> {
    let live = read_json(live_ca_json)?;
    let mut staged = read_json(staged_ca_json)?;
    let live_jwks = live_jwk_provisioners(&live, live_ca_json)?;
    let active_jwks = active_jwk_provisioners(model);
    let mut replacements = BTreeMap::new();

    for provisioner in &active_jwks {
        let object = if let Some(live) = live_jwks.get(&provisioner.name) {
            runtime_jwk_from_live(model, provisioner, live, jwk_dir)?
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

    let mut names = provisioners
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let user_policy = active_provisioner(model, PROVISIONER_ROLE_USER_ENROLLMENT)?;
    let host_policy = active_provisioner(model, PROVISIONER_ROLE_HOST_BOOTSTRAP)?;
    for (name, mut item) in live_jwks {
        let desired = if parse_user_provisioner_name(&name).is_some() {
            user_renewal_claims(model, user_policy)
        } else if parse_host_provisioner_name(&name).is_some() {
            host_renewal_claims(model, host_policy)
        } else {
            continue;
        };
        require_object_field(&item, "key", &name)?;
        if !names.insert(name.clone()) {
            return Err(Error::Validation {
                field: format!("{}:authority.provisioners", staged_ca_json.display()),
                message: format!("renewal provisioner {name} collides with staged state"),
            });
        }
        item.as_object_mut()
            .expect("live JWK provisioner is an object")
            .remove("encryptedKey");
        reconcile_provisioner_claims(&mut item, &name, desired, live_ca_json)?;
        provisioners.push(item);
    }

    serde_json::to_string_pretty(&staged).map_err(|source| Error::Json {
        path: staged_ca_json.to_path_buf(),
        source,
    })
}

#[cfg(test)]
fn add_user_client(
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

    let desired =
        user_client_provisioner(key, name, template, user_claims_for(default_ttl, max_ttl));
    upsert_renewal_provisioner(provisioners, desired, ca_json)?;

    serialize_config(config, ca_json)
}

/// Reconcile the user enrollment issuer and one constrained user/client-host issuer.
///
/// The enrollment provisioner authorizes the first certificate while the renewal provisioner
/// authorizes later renewals. Updating both in one serialized configuration keeps issuance and
/// renewal on the same policy before the caller activates the CA state.
pub fn reconcile_user_client(
    model: &SiteModel,
    ca_json: impl AsRef<Path>,
    public_key: impl AsRef<Path>,
    name: &str,
    template_file: &str,
) -> Result<String> {
    let ca_json = ca_json.as_ref();
    let public_key = public_key.as_ref();
    let mut config = read_json(ca_json)?;
    let key = read_public_jwk(public_key)?;
    let template = read_text(Path::new(template_file))?;
    let policy = active_provisioner(model, PROVISIONER_ROLE_USER_ENROLLMENT)?;
    let provisioners = provisioners_mut(&mut config, ca_json)?;

    reconcile_required_provisioner(provisioners, policy, user_claims(policy), ca_json)?;
    let desired = user_client_provisioner(key, name, template, user_renewal_claims(model, policy));
    upsert_renewal_provisioner(provisioners, desired, ca_json)?;

    serialize_config(config, ca_json)
}

#[cfg(test)]
fn add_host(
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
    // A retained SSHPOP provisioner would bypass device-bound revocation.
    provisioners.retain(|item| item.get("type").and_then(Value::as_str) != Some("SSHPOP"));

    let desired = host_provisioner(key, name, template, host_claims_for(default_ttl, max_ttl));
    upsert_renewal_provisioner(provisioners, desired, ca_json)?;

    serialize_config(config, ca_json)
}

/// Reconcile the host bootstrap issuer and one constrained host issuer.
///
/// The bootstrap provisioner authorizes the first certificate while the renewal provisioner
/// authorizes later renewals. Updating both in one serialized configuration keeps issuance and
/// renewal on the same policy before the caller activates the CA state.
pub fn reconcile_host(
    model: &SiteModel,
    ca_json: impl AsRef<Path>,
    public_key: impl AsRef<Path>,
    name: &str,
    template_file: &str,
) -> Result<String> {
    let ca_json = ca_json.as_ref();
    let public_key = public_key.as_ref();
    let mut config = read_json(ca_json)?;
    let key = read_public_jwk(public_key)?;
    let template = read_text(Path::new(template_file))?;
    let policy = active_provisioner(model, PROVISIONER_ROLE_HOST_BOOTSTRAP)?;
    let provisioners = provisioners_mut(&mut config, ca_json)?;
    // A retained SSHPOP provisioner would bypass device-bound revocation.
    provisioners.retain(|item| item.get("type").and_then(Value::as_str) != Some("SSHPOP"));

    reconcile_required_provisioner(provisioners, policy, host_claims(policy), ca_json)?;
    let desired = host_provisioner(key, name, template, host_renewal_claims(model, policy));
    upsert_renewal_provisioner(provisioners, desired, ca_json)?;

    serialize_config(config, ca_json)
}

/// Remove one exact renewal JWK provisioner from an existing CA config.
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
    validate_public_jwk(&key, &path.display().to_string())?;
    Ok(key)
}

/// Extract the RFC public key members from an EC, OKP, or RSA JWK.
pub fn jwk_public_material(jwk: &Value, field: &str) -> Result<Value> {
    let object = jwk.as_object().ok_or_else(|| Error::Validation {
        field: field.to_owned(),
        message: "JWK must be a JSON object".to_owned(),
    })?;
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Validation {
            field: field.to_owned(),
            message: "JWK must have a string kty".to_owned(),
        })?;
    let members: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "RSA" => &["e", "kty", "n"],
        _ => {
            return Err(Error::Validation {
                field: field.to_owned(),
                message: format!("unsupported JWK type {kty}"),
            });
        }
    };
    let mut material = Map::new();
    for member in members {
        let value =
            object
                .get(*member)
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Validation {
                    field: field.to_owned(),
                    message: format!("JWK must have a string {member}"),
                })?;
        material.insert((*member).to_owned(), Value::String(value.to_owned()));
    }
    Ok(Value::Object(material))
}

/// Validate that a JWK contains only public key material and return its RFC members.
pub fn validate_public_jwk(jwk: &Value, field: &str) -> Result<Value> {
    let object = jwk.as_object().ok_or_else(|| Error::Validation {
        field: field.to_owned(),
        message: "public JWK must be a JSON object".to_owned(),
    })?;
    if ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(Error::Validation {
            field: field.to_owned(),
            message: "public JWK must not contain private key material".to_owned(),
        });
    }
    jwk_public_material(jwk, field)
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
        if by_name.insert(name.to_owned(), item.clone()).is_some() {
            return Err(Error::Validation {
                field: format!("{}:authority.provisioners", path.display()),
                message: format!("duplicate live JWK provisioner {name}"),
            });
        }
    }
    Ok(by_name)
}

fn runtime_jwk_from_live(
    model: &SiteModel,
    provisioner: &Provisioner,
    live: &Value,
    jwk_dir: &Path,
) -> Result<Value> {
    let mut object = live.clone();
    require_object_field(&object, "key", &provisioner.name)?;
    let live_key = &object["key"];
    let public_path = jwk_dir.join(format!("{}.pub.json", provisioner.name));
    let public = read_public_jwk(&public_path)?;
    require_enrollment_credential_files(jwk_dir, &provisioner.name)?;
    if jwk_public_material(
        live_key,
        &format!("live provisioner {}.key", provisioner.name),
    )? != validate_public_jwk(&public, &public_path.display().to_string())?
    {
        return Err(Error::Validation {
            field: public_path.display().to_string(),
            message: format!(
                "public JWK does not match live enrollment provisioner {}",
                provisioner.name
            ),
        });
    }
    object
        .as_object_mut()
        .expect("live JWK provisioner is an object")
        .remove("encryptedKey");
    object["type"] = json!("JWK");
    object["name"] = json!(provisioner.name);
    object["claims"] = crate::render::active_provisioner_claims(model, &provisioner.name)?;
    if let Some(options) = enrollment_options(provisioner) {
        object["options"] = options;
    }
    Ok(object)
}

fn runtime_jwk_from_files(
    model: &SiteModel,
    provisioner: &Provisioner,
    jwk_dir: &Path,
) -> Result<Value> {
    let public_path = jwk_dir.join(format!("{}.pub.json", provisioner.name));
    let public = read_public_jwk(&public_path)?;
    require_enrollment_credential_files(jwk_dir, &provisioner.name)?;
    let mut object = json!({
        "type": "JWK",
        "name": provisioner.name,
        "key": public,
        "claims": crate::render::active_provisioner_claims(model, &provisioner.name)?,
    });
    if let Some(options) = enrollment_options(provisioner) {
        object["options"] = options;
    }
    Ok(object)
}

/// Prove that one server-local enrollment key can sign for its live public JWK.
pub fn validate_enrollment_provisioner_key_files(
    model: &SiteModel,
    jwk_dir: &Path,
    name: &str,
    expected_live_key: &Value,
    step_bin: &Path,
) -> Result<()> {
    let public_path = jwk_dir.join(format!("{name}.pub.json"));
    let public_metadata = std::fs::symlink_metadata(&public_path)
        .map_err(|source| Error::io(&public_path, source))?;
    if !public_metadata.file_type().is_file() {
        return Err(Error::Validation {
            field: public_path.display().to_string(),
            message: "enrollment provisioner public JWK must be a regular file".to_owned(),
        });
    }
    let public = read_json(&public_path)?;
    let public_material = validate_public_jwk(&public, &public_path.display().to_string())?;
    let expected_material = jwk_public_material(
        expected_live_key,
        &format!("live enrollment provisioner {name}.key"),
    )?;
    if public_material != expected_material {
        return Err(Error::Validation {
            field: public_path.display().to_string(),
            message: format!("public JWK does not match live enrollment provisioner {name}"),
        });
    }

    require_enrollment_credential_files(jwk_dir, name)?;
    let private_path = jwk_dir.join(format!("{name}.priv.json"));
    let password_path = jwk_dir.join(format!("{name}.password"));
    let password =
        std::fs::read(&password_path).map_err(|source| Error::io(&password_path, source))?;
    let intermediate_path = Path::new(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]);
    let intermediate =
        std::fs::read(intermediate_path).map_err(|source| Error::io(intermediate_path, source))?;
    if password == intermediate {
        return Err(Error::Validation {
            field: password_path.display().to_string(),
            message:
                "enrollment provisioner password must differ from the intermediate CA password"
                    .to_owned(),
        });
    }

    let encrypted = read_json(&private_path)?;
    let encrypted = encrypted.as_object().ok_or_else(|| Error::Validation {
        field: private_path.display().to_string(),
        message: "enrollment provisioner private key must be an encrypted JWE object".to_owned(),
    })?;
    if !["protected", "iv", "ciphertext", "tag", "encrypted_key"]
        .iter()
        .all(|field| encrypted.get(*field).and_then(Value::as_str).is_some())
    {
        return Err(Error::Validation {
            field: private_path.display().to_string(),
            message: "enrollment provisioner private key must be an encrypted JWE object"
                .to_owned(),
        });
    }

    let temp = tempfile::Builder::new()
        .prefix(".grafhome-ca-enrollment-key-check-")
        .tempdir_in(jwk_dir)
        .map_err(|source| Error::io(jwk_dir, source))?;
    let plaintext = temp.path().join("plaintext.jwk");
    let status = Command::new(step_bin)
        .arg("crypto")
        .arg("key")
        .arg("format")
        .arg(&private_path)
        .arg("--jwk")
        .arg("--password-file")
        .arg(&password_path)
        .arg("--out")
        .arg(&plaintext)
        .arg("--insecure")
        .arg("--no-password")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| Error::io(step_bin, source))?;
    if !status.success() {
        return Err(Error::Validation {
            field: private_path.display().to_string(),
            message: format!(
                "encrypted private JWK could not be decrypted with its password for {name}"
            ),
        });
    }
    let private = read_json(&plaintext)?;
    if jwk_public_material(&private, &plaintext.display().to_string())? != public_material {
        return Err(Error::Validation {
            field: private_path.display().to_string(),
            message: format!("encrypted private JWK does not match public JWK for {name}"),
        });
    }
    Ok(())
}

fn require_enrollment_credential_files(jwk_dir: &Path, name: &str) -> Result<()> {
    for suffix in ["priv.json", "password"] {
        let path = jwk_dir.join(format!("{name}.{suffix}"));
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|source| Error::io(&path, source))?;
        if !metadata.file_type().is_file() {
            return Err(Error::Validation {
                field: path.display().to_string(),
                message: "enrollment provisioner credential must be a regular file".to_owned(),
            });
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Validation {
                field: path.display().to_string(),
                message:
                    "enrollment provisioner credential must not be accessible by group or others"
                        .to_owned(),
            });
        }
        if std::fs::read(&path)
            .map_err(|source| Error::io(&path, source))?
            .is_empty()
        {
            return Err(Error::Validation {
                field: path.display().to_string(),
                message: "enrollment provisioner credential must not be empty".to_owned(),
            });
        }
    }
    Ok(())
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
        assert_eq!(client["claims"]["maxUserSSHCertDuration"], "48h");
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
    fn reconcile_user_client_rejects_missing_enrollment_issuer() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, "user-template").unwrap();

        let error = reconcile_user_client(
            &model,
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("required live provisioner grafhome-user-enrollment is missing")
        );
        assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
    }

    #[test]
    fn reconcile_user_client_rejects_duplicate_enrollment_issuers() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[{"name":"grafhome-user-enrollment"},{"name":"grafhome-user-enrollment"}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, "user-template").unwrap();

        let error = reconcile_user_client(
            &model,
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("provisioner grafhome-user-enrollment appears more than once")
        );
        assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
    }

    #[test]
    fn reconcile_user_client_rejects_wrong_enrollment_issuer_type() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[{"type":"ACME","name":"grafhome-user-enrollment","key":{},"encryptedKey":"encrypted"}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, "user-template").unwrap();

        let error = reconcile_user_client(
            &model,
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("provisioner grafhome-user-enrollment must have type JWK")
        );
        assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
    }

    #[test]
    fn reconcile_user_client_accepts_public_only_enrollment_issuer() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-user-enrollment","key":{}}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
        let template = dir.path().join("user.tpl");
        fs::write(&template, "user-template").unwrap();

        let result = reconcile_user_client(
            &model,
            &ca_json,
            &public_key,
            "grafhome-user-alice-ca-host",
            template.to_str().unwrap(),
        )
        .unwrap();

        assert!(!result.contains("encryptedKey"));
        assert!(result.contains("x509 issuance disabled for Grafhome user enrollment"));
        assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
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
                    "key": {"kid": "bootstrap-kid", "kty": "EC", "crv": "P-256", "x": "bootstrap-x", "y": "bootstrap-y"},
                    "encryptedKey": "encrypted-bootstrap",
                    "claims": {"enableSSHCA": true}
                  },
                  {
                    "type": "JWK",
                    "name": "grafhome-user-616c696365-63612d686f7374",
                    "key": {"kid": "existing-user-renewal"},
                    "encryptedKey": "remove-accidental-user-secret",
                    "claims": {
                      "defaultUserSSHCertDuration": "12h",
                      "maxUserSSHCertDuration": "2562047h",
                      "operatorClaim": true
                    },
                    "options": {
                      "x509": {"template": "existing-user-x509"},
                      "ssh": {"template": "existing-user-template"}
                    }
                  },
                  {
                    "type": "JWK",
                    "name": "grafhome-host-70726f78792d686f7374",
                    "key": {"kid": "existing-host-renewal"},
                    "claims": {
                      "defaultHostSSHCertDuration": "24h",
                      "maxHostSSHCertDuration": "2562047h"
                    },
                    "options": {
                      "x509": {"template": "existing-host-x509"},
                      "ssh": {"template": "existing-host-template", "templateFile": "preserve.tpl"}
                    }
                  }
                ]
              }
            }"#,
        )
        .unwrap();
        let jwk_dir = dir.path().join("provisioners");
        fs::create_dir(&jwk_dir).unwrap();
        for (name, public) in [
            (
                "grafhome-host-bootstrap",
                r#"{"kid":"bootstrap-kid","kty":"EC","crv":"P-256","x":"bootstrap-x","y":"bootstrap-y"}"#,
            ),
            (
                "grafhome-user-enrollment",
                r#"{"kid":"user-enrollment-kid","kty":"EC","crv":"P-256","x":"enrollment-x","y":"enrollment-y"}"#,
            ),
        ] {
            fs::write(jwk_dir.join(format!("{name}.pub.json")), public).unwrap();
            let private = jwk_dir.join(format!("{name}.priv.json"));
            let password = jwk_dir.join(format!("{name}.password"));
            fs::write(&private, r#"{"protected":"jwe"}"#).unwrap();
            fs::write(&password, "independent-password").unwrap();
            #[cfg(unix)]
            {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
                fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        let text = merge_materialized(&model, &live_path, &staged_path, &jwk_dir).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let provisioners = value["authority"]["provisioners"].as_array().unwrap();

        assert!(!text.contains("RUNTIME_SECRET_PLACEHOLDER"));
        let bootstrap = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-host-bootstrap")
            .unwrap();
        assert_eq!(bootstrap["key"]["kid"], "bootstrap-kid");
        assert!(bootstrap.get("encryptedKey").is_none());
        assert!(
            bootstrap["options"]["ssh"]["template"]
                .as_str()
                .unwrap()
                .contains("\"type\": \"host\"")
        );
        assert_eq!(bootstrap["claims"]["defaultHostSSHCertDuration"], "168h");
        let user_enrollment = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-user-enrollment")
            .unwrap();
        assert_eq!(user_enrollment["key"]["kid"], "user-enrollment-kid");
        assert!(user_enrollment.get("encryptedKey").is_none());
        assert_eq!(
            user_enrollment["claims"]["defaultUserSSHCertDuration"],
            "24h"
        );
        let user_renewal = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-user-616c696365-63612d686f7374")
            .unwrap();
        assert_eq!(user_renewal["key"]["kid"], "existing-user-renewal");
        assert_eq!(
            user_renewal["options"]["ssh"]["template"],
            "existing-user-template"
        );
        assert_eq!(user_renewal["claims"]["defaultUserSSHCertDuration"], "24h");
        assert_eq!(user_renewal["claims"]["maxUserSSHCertDuration"], "48h");
        assert_eq!(user_renewal["claims"]["operatorClaim"], true);
        assert!(user_renewal.get("encryptedKey").is_none());
        let host_renewal = provisioners
            .iter()
            .find(|item| item["name"] == "grafhome-host-70726f78792d686f7374")
            .unwrap();
        assert_eq!(host_renewal["key"]["kid"], "existing-host-renewal");
        assert_eq!(
            host_renewal["options"]["ssh"]["templateFile"],
            "preserve.tpl"
        );
        assert_eq!(host_renewal["claims"]["defaultHostSSHCertDuration"], "168h");
        assert_eq!(host_renewal["claims"]["maxHostSSHCertDuration"], "720h");
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
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
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
                            "key": {"kid": "client-kid", "kty": "EC", "crv": "P-256", "x": "client-x", "y": "client-y"},
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
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
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
        fs::write(
            &public_key,
            r#"{"kid":"host-kid","kty":"EC","crv":"P-256","x":"host-x","y":"host-y"}"#,
        )
        .unwrap();
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
                        "key": {"kid": "host-kid", "kty": "EC", "crv": "P-256", "x": "host-x", "y": "host-y"},
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
        fs::write(
            &public_key,
            r#"{"kid":"host-kid","kty":"EC","crv":"P-256","x":"host-x","y":"host-y"}"#,
        )
        .unwrap();
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
        let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-user-alice-ca-host","key":{"kid":"other","kty":"EC","crv":"P-256","x":"other-x","y":"other-y"}}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
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
        let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-host-edge","key":{"kid":"other","kty":"EC","crv":"P-256","x":"other-x","y":"other-y"}}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"host-kid","kty":"EC","crv":"P-256","x":"host-x","y":"host-y"}"#,
        )
        .unwrap();
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
    fn rejects_duplicate_renewal_provisioner_names() {
        let dir = tempdir().unwrap();
        let ca_json = dir.path().join("ca.json");
        let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-user-alice-ca-host","key":{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}},{"type":"JWK","name":"grafhome-user-alice-ca-host","key":{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}}]}}"#;
        fs::write(&ca_json, original).unwrap();
        let public_key = dir.path().join("provisioner.pub.json");
        fs::write(
            &public_key,
            r#"{"kid":"client-kid","kty":"EC","crv":"P-256","x":"client-x","y":"client-y"}"#,
        )
        .unwrap();
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

        let error = merge_materialized(&model, &live_path, &staged_path, &jwk_dir).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("grafhome-host-bootstrap.pub.json")
        );
    }

    #[test]
    fn live_enrollment_provisioner_rejects_a_mismatched_canonical_public_key() {
        let dir = tempdir().unwrap();
        let model = SiteModel::load(crate::example_config_root()).unwrap();
        let provisioner = active_provisioner(&model, "host_bootstrap").unwrap();
        let private = dir.path().join(format!("{}.priv.json", provisioner.name));
        let password = dir.path().join(format!("{}.password", provisioner.name));
        fs::write(
            dir.path().join(format!("{}.pub.json", provisioner.name)),
            r#"{"kty":"EC","crv":"P-256","x":"wrong-x","y":"wrong-y"}"#,
        )
        .unwrap();
        fs::write(&private, "encrypted").unwrap();
        fs::write(&password, "independent-password").unwrap();
        #[cfg(unix)]
        {
            fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let live = json!({
            "type": "JWK",
            "name": provisioner.name,
            "key": {"kty":"EC","crv":"P-256","x":"live-x","y":"live-y"}
        });

        let error = runtime_jwk_from_live(&model, provisioner, &live, dir.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not match live enrollment provisioner"));
    }
}
