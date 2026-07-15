//! JSON Schema validation for site configuration.

use std::path::{Path, PathBuf};

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
    let schema_name = schema_path.display().to_string();
    validate_schema_text(&schema_name, &schema_name, &schema_text, value)
}

fn validate_schema_text(
    schema_name: &str,
    document_name: &str,
    schema_text: &str,
    value: &Value,
) -> Result<()> {
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
            field: document_name.to_owned(),
            message: format!("schema {schema_name}: {}", errors.join("; ")),
        })
    }
}

/// Validate site config files against embedded public schemas.
pub fn validate_config_root(config_root: impl AsRef<Path>) -> Result<()> {
    let config_root = config_root.as_ref();
    let deployment = crate::config::Deployment::load(config_root.join("config/deployment.env"))?;
    validate_schema_text(
        "schemas/config/deployment-env.schema.json",
        "config/deployment.env",
        include_str!("../schemas/config/deployment-env.schema.json"),
        &serde_json::to_value(&deployment.values).expect("deployment serializes"),
    )?;

    match policy::format(config_root)? {
        policy::Format::Canonical => validate_canonical_policy(config_root)?,
        policy::Format::Legacy => {
            for spec in legacy_policy_specs() {
                validate_policy_file(config_root, spec.path, spec)?;
            }
        }
    }
    Ok(())
}

/// Return every file that defines the site configuration and policy model.
///
/// Security checks and schema validation share this inventory so a newly added
/// policy input cannot accidentally bypass privileged-command provenance checks.
pub fn config_input_paths(config_root: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    let mut paths = vec![PathBuf::from("config/deployment.env")];
    paths.extend(policy::input_paths(config_root)?);
    Ok(paths)
}

struct PolicySpec {
    path: &'static str,
    schema: &'static str,
    schema_text: &'static str,
}

fn legacy_policy_specs() -> &'static [PolicySpec] {
    &[
        PolicySpec {
            path: policy::LEGACY_ENDPOINTS_PATH,
            schema: "schemas/policy/legacy/endpoints.schema.json",
            schema_text: include_str!("../schemas/policy/legacy/endpoints.schema.json"),
        },
        PolicySpec {
            path: policy::LEGACY_HOSTS_PATH,
            schema: "schemas/policy/legacy/hosts.schema.json",
            schema_text: include_str!("../schemas/policy/legacy/hosts.schema.json"),
        },
        PolicySpec {
            path: policy::USERS_POLICY_PATH,
            schema: "schemas/policy/legacy/users.schema.json",
            schema_text: include_str!("../schemas/policy/legacy/users.schema.json"),
        },
        PolicySpec {
            path: policy::LEGACY_PROVISIONERS_PATH,
            schema: "schemas/policy/legacy/provisioners.schema.json",
            schema_text: include_str!("../schemas/policy/legacy/provisioners.schema.json"),
        },
        PolicySpec {
            path: policy::LEGACY_USER_CLIENTS_PATH,
            schema: "schemas/policy/legacy/user-clients.schema.json",
            schema_text: include_str!("../schemas/policy/legacy/user-clients.schema.json"),
        },
        PolicySpec {
            path: policy::LEGACY_USER_REMOTES_PATH,
            schema: "schemas/policy/legacy/user-remotes.schema.json",
            schema_text: include_str!("../schemas/policy/legacy/user-remotes.schema.json"),
        },
    ]
}

fn validate_canonical_policy(config_root: &Path) -> Result<()> {
    let ca = PolicySpec {
        path: policy::CA_POLICY_PATH,
        schema: "schemas/policy/ca.schema.json",
        schema_text: include_str!("../schemas/policy/ca.schema.json"),
    };
    validate_policy_file(config_root, ca.path, &ca)?;
    let users = PolicySpec {
        path: policy::USERS_POLICY_PATH,
        schema: "schemas/policy/canonical/users.schema.json",
        schema_text: include_str!("../schemas/policy/canonical/users.schema.json"),
    };
    validate_policy_file(config_root, users.path, &users)?;
    let host_schema = include_str!("../schemas/policy/host.schema.json");
    for path in policy::input_paths(config_root)?
        .into_iter()
        .filter(|path| path.starts_with(policy::HOST_POLICY_DIR))
    {
        let document = policy::read_document(config_root.join(&path))?;
        validate_schema_text(
            "schemas/policy/host.schema.json",
            &path.display().to_string(),
            host_schema,
            &document,
        )?;
    }
    Ok(())
}

fn validate_policy_file(config_root: &Path, path: &str, spec: &PolicySpec) -> Result<()> {
    let document = policy::read_document(config_root.join(path))?;
    validate_schema_text(spec.schema, path, spec.schema_text, &document)
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
        let hosts = dir.path().join("policy/hosts/ca-host.toml");
        let text = fs::read_to_string(&hosts).unwrap().replacen(
            "ssh_server = true",
            "ssh_server = true\nlegacy_flag = true",
            1,
        );
        fs::write(hosts, text).unwrap();

        let error = crate::schema::validate_config_root(dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("Additional properties are not allowed"));
        assert!(error.contains("legacy_flag"));
        assert!(error.contains("policy/hosts/ca-host.toml"));
    }

    #[test]
    fn schema_rejects_unlimited_maximum_for_host_provisioner() {
        let dir = tempdir().unwrap();
        copy_dir(&example_config_root(), dir.path());
        let provisioners = dir.path().join("policy/ca.toml");
        let text = fs::read_to_string(&provisioners).unwrap().replacen(
            "max_ttl = \"720h\"",
            "max_ttl = \"unlimited\"",
            1,
        );
        fs::write(provisioners, text).unwrap();

        let error = crate::schema::validate_config_root(dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unlimited"));
    }

    #[test]
    fn published_legacy_schema_entry_points_remain_compatible() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/policy");
        for name in [
            "endpoints",
            "hosts",
            "provisioners",
            "user-clients",
            "user-remotes",
        ] {
            let document: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(root.join(format!("{name}.schema.json"))).unwrap(),
            )
            .unwrap();
            assert_eq!(
                document["$id"],
                format!(
                    "https://raw.githubusercontent.com/cgraf78/grafhome-ca/main/schemas/policy/{name}.schema.json"
                )
            );
            assert_eq!(document["$ref"], format!("legacy/{name}.schema.json"));
        }

        let users: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("users.schema.json")).unwrap())
                .unwrap();
        assert_eq!(users["oneOf"][0]["$ref"], "legacy/users.schema.json");
        assert_eq!(users["oneOf"][1]["$ref"], "canonical/users.schema.json");
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
