use std::path::{Path, PathBuf};

#[test]
fn checked_in_deployment_inputs_do_not_contain_secret_material() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let paths = source_inputs(root);
    assert!(!paths.is_empty());

    for path in paths {
        let text = std::fs::read_to_string(&path).unwrap();
        for label in PRIVATE_KEY_LABELS {
            let header = format!("-----BEGIN {label}-----");
            assert!(
                !text.contains(&header),
                "{} contains private key material marker {header}",
                path.display()
            );
        }
        assert!(
            !text.contains("\"encryptedKey\""),
            "{} contains a Smallstep encrypted provisioner key",
            path.display()
        );
        assert!(
            !text.contains("BEGIN AGE ENCRYPTED FILE"),
            "{} contains encrypted secret payload material",
            path.display()
        );
    }
}

const PRIVATE_KEY_LABELS: &[&str] = &[
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
];

fn source_inputs(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for name in ["examples", "schemas", "templates"] {
        collect_files(&root.join(name), &mut paths);
    }
    paths.sort();
    paths
}

fn collect_files(path: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, paths);
        } else {
            paths.push(path);
        }
    }
}
