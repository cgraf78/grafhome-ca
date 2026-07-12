//! JSON Schema validation for site configuration.

use std::path::Path;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::policy;

/// Validate JSON data against a JSON Schema file.
///
/// This lower-level helper remains useful for tests and local tooling that need
/// to validate arbitrary JSON against a schema path. The normal CLI path uses
/// the embedded schemas below so runtime site config does not need a source
/// checkout beside it.
pub fn validate(schema_path: impl AsRef<Path>, value: &Value) -> Result<()> {
    let schema_path = schema_path.as_ref();
    let schema_text =
        std::fs::read_to_string(schema_path).map_err(|source| Error::io(schema_path, source))?;
    validate_schema_text(&schema_path.display().to_string(), &schema_text, value)
}

fn validate_schema_text(schema_name: &str, schema_text: &str, value: &Value) -> Result<()> {
    let schema: Value = serde_json::from_str(schema_text).map_err(|source| Error::Json {
        path: Path::new(schema_name).to_path_buf(),
        source,
    })?;
    let compiled =
        jsonschema::JSONSchema::compile(&schema).map_err(|source| Error::Validation {
            field: schema_name.to_owned(),
            message: source.to_string(),
        })?;
    let errors = compiled
        .validate(value)
        .err()
        .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::Validation {
            field: schema_name.to_owned(),
            message: errors.join("; "),
        })
    }
}

/// Validate site config files against embedded public schemas.
pub fn validate_config_root(config_root: impl AsRef<Path>) -> Result<()> {
    let config_root = config_root.as_ref();
    let deployment = crate::config::Deployment::load(config_root.join("config/deployment.env"))?;
    validate_schema_text(
        "schemas/config/deployment-env.schema.json",
        include_str!("../schemas/config/deployment-env.schema.json"),
        &serde_json::to_value(&deployment.values).expect("deployment serializes"),
    )?;

    for spec in policy_specs() {
        let rows = policy::read_raw(config_root.join(spec.path), spec.headers)?;
        validate_schema_text(
            spec.schema,
            spec.schema_text,
            &serde_json::to_value(rows).expect("policy rows serialize"),
        )?;
    }
    Ok(())
}

/// Return every file that defines the site configuration and policy model.
///
/// Security checks and schema validation share this inventory so a newly added
/// policy input cannot accidentally bypass privileged-command provenance checks.
pub fn config_input_paths() -> impl Iterator<Item = &'static str> {
    std::iter::once("config/deployment.env").chain(policy_specs().iter().map(|spec| spec.path))
}

struct PolicySpec {
    path: &'static str,
    schema: &'static str,
    schema_text: &'static str,
    headers: &'static [&'static str],
}

fn policy_specs() -> &'static [PolicySpec] {
    &[
        PolicySpec {
            path: "policy/endpoints.tsv",
            schema: "schemas/policy/endpoints.schema.json",
            schema_text: include_str!("../schemas/policy/endpoints.schema.json"),
            headers: &[
                "role",
                "name",
                "dns_name",
                "target",
                "interface",
                "address",
                "port",
                "scheme",
            ],
        },
        PolicySpec {
            path: "policy/hosts.tsv",
            schema: "schemas/policy/hosts.schema.json",
            schema_text: include_str!("../schemas/policy/hosts.schema.json"),
            headers: &[
                "host",
                "kind",
                "ssh_server",
                "ssh_client",
                "renewal_owner",
                "principals",
            ],
        },
        PolicySpec {
            path: "policy/users.tsv",
            schema: "schemas/policy/users.schema.json",
            schema_text: include_str!("../schemas/policy/users.schema.json"),
            headers: &[
                "user",
                "principal",
                "unix_account",
                "root_ssh",
                "provisioner",
                "cert_ttl",
                "status",
                "notes",
            ],
        },
        PolicySpec {
            path: "policy/operators.tsv",
            schema: "schemas/policy/operators.schema.json",
            schema_text: include_str!("../schemas/policy/operators.schema.json"),
            headers: &[
                "user",
                "host_ref",
                "unix_account",
                "privilege",
                "status",
                "notes",
            ],
        },
        PolicySpec {
            path: "policy/provisioners.tsv",
            schema: "schemas/policy/provisioners.schema.json",
            schema_text: include_str!("../schemas/policy/provisioners.schema.json"),
            headers: &[
                "role",
                "name",
                "type",
                "default_ttl",
                "max_ttl",
                "renewal_check",
                "status",
                "notes",
            ],
        },
        PolicySpec {
            path: "policy/client-devices.tsv",
            schema: "schemas/policy/client-devices.schema.json",
            schema_text: include_str!("../schemas/policy/client-devices.schema.json"),
            headers: &["device", "owner", "user", "key_name", "status"],
        },
        PolicySpec {
            path: "policy/principals.tsv",
            schema: "schemas/policy/principals.schema.json",
            schema_text: include_str!("../schemas/policy/principals.schema.json"),
            headers: &["principal", "type", "owner", "allowed_accounts", "notes"],
        },
        PolicySpec {
            path: "policy/user-hosts.tsv",
            schema: "schemas/policy/user-hosts.schema.json",
            schema_text: include_str!("../schemas/policy/user-hosts.schema.json"),
            headers: &[
                "user",
                "host",
                "unix_account",
                "allow_ssh",
                "sudo_expected",
                "status",
                "notes",
            ],
        },
        PolicySpec {
            path: "policy/automation.tsv",
            schema: "schemas/policy/automation.schema.json",
            schema_text: include_str!("../schemas/policy/automation.schema.json"),
            headers: &[
                "name",
                "source_ref",
                "target_ref",
                "purpose",
                "auth_model",
                "notes",
            ],
        },
        PolicySpec {
            path: "policy/static-keys.tsv",
            schema: "schemas/policy/static-keys.schema.json",
            schema_text: include_str!("../schemas/policy/static-keys.schema.json"),
            headers: &[
                "account",
                "host_ref",
                "purpose",
                "class",
                "required_controls",
            ],
        },
        PolicySpec {
            path: "policy/emergency-access.tsv",
            schema: "schemas/policy/emergency-access.schema.json",
            schema_text: include_str!("../schemas/policy/emergency-access.schema.json"),
            headers: &["host", "account", "key_id", "storage", "test_interval"],
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn example_config_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/site-config")
    }

    #[test]
    fn example_files_match_embedded_schemas() {
        crate::schema::validate_config_root(example_config_root()).expect("schema validation");
    }
}
