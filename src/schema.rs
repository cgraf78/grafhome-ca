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
        let document = policy::read_document(config_root.join(spec.path))?;
        validate_schema_text(spec.schema, spec.schema_text, &document)?;
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
}

fn policy_specs() -> &'static [PolicySpec] {
    &[
        PolicySpec {
            path: "policy/endpoints.toml",
            schema: "schemas/policy/endpoints.schema.json",
            schema_text: include_str!("../schemas/policy/endpoints.schema.json"),
        },
        PolicySpec {
            path: "policy/hosts.toml",
            schema: "schemas/policy/hosts.schema.json",
            schema_text: include_str!("../schemas/policy/hosts.schema.json"),
        },
        PolicySpec {
            path: "policy/users.toml",
            schema: "schemas/policy/users.schema.json",
            schema_text: include_str!("../schemas/policy/users.schema.json"),
        },
        PolicySpec {
            path: "policy/provisioners.toml",
            schema: "schemas/policy/provisioners.schema.json",
            schema_text: include_str!("../schemas/policy/provisioners.schema.json"),
        },
        PolicySpec {
            path: "policy/user-clients.toml",
            schema: "schemas/policy/user-clients.schema.json",
            schema_text: include_str!("../schemas/policy/user-clients.schema.json"),
        },
        PolicySpec {
            path: "policy/user-remotes.toml",
            schema: "schemas/policy/user-remotes.schema.json",
            schema_text: include_str!("../schemas/policy/user-remotes.schema.json"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    fn example_config_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/site-config")
    }

    #[test]
    fn example_files_match_embedded_schemas() {
        crate::schema::validate_config_root(example_config_root()).expect("schema validation");
    }

    #[test]
    fn schema_rejects_unknown_toml_fields() {
        let dir = tempdir().unwrap();
        copy_dir(&example_config_root(), dir.path());
        let hosts = dir.path().join("policy/hosts.toml");
        let text = fs::read_to_string(&hosts).unwrap().replacen(
            "host = \"ca-host\"",
            "host = \"ca-host\"\nlegacy_flag = true",
            1,
        );
        fs::write(hosts, text).unwrap();

        let error = crate::schema::validate_config_root(dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("Additional properties are not allowed"));
        assert!(error.contains("legacy_flag"));
    }

    #[test]
    fn schema_rejects_unlimited_maximum_for_host_provisioner() {
        let dir = tempdir().unwrap();
        copy_dir(&example_config_root(), dir.path());
        let provisioners = dir.path().join("policy/provisioners.toml");
        let text = fs::read_to_string(&provisioners).unwrap().replacen(
            "max_ttl = \"720h\"",
            "max_ttl = \"unlimited\"",
            1,
        );
        fs::write(provisioners, text).unwrap();

        let error = crate::schema::validate_config_root(dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("user_enrollment"));
    }

    fn copy_dir(source: &std::path::Path, destination: &std::path::Path) {
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir(&target).unwrap();
                copy_dir(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }
}
