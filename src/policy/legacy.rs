//! Compatibility reader for the normalized six-file policy layout.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use super::{
    Host, LEGACY_ENDPOINTS_PATH, LEGACY_HOSTS_PATH, LEGACY_PROVISIONERS_PATH,
    LEGACY_USER_CLIENTS_PATH, LEGACY_USER_REMOTES_PATH, Policy, SshRole, USERS_POLICY_PATH, User,
    read_toml, read_typed_document,
};
use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsersDocument {
    #[serde(default)]
    require_ssh_admin_access: bool,
    users: Vec<User>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyHost {
    host: String,
    ssh_server: bool,
    ssh_client: bool,
    principals: Vec<String>,
}

/// Normalize legacy documents into the shared policy model.
pub(super) fn load(root: &Path) -> Result<Policy> {
    let endpoints = read_array(root.join(LEGACY_ENDPOINTS_PATH), "endpoints")?;
    let hosts = read_array::<LegacyHost>(root.join(LEGACY_HOSTS_PATH), "hosts")?
        .into_iter()
        .map(|host| Host {
            host: host.host,
            ssh_roles: [
                host.ssh_server.then_some(SshRole::Server),
                host.ssh_client.then_some(SshRole::Client),
            ]
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>(),
            principals: host.principals,
        })
        .collect();
    let users: UsersDocument = read_document(root.join(USERS_POLICY_PATH))?;
    let provisioners = read_array(root.join(LEGACY_PROVISIONERS_PATH), "provisioners")?;
    let user_clients = read_array(root.join(LEGACY_USER_CLIENTS_PATH), "user_clients")?;
    let user_remotes = read_array(root.join(LEGACY_USER_REMOTES_PATH), "user_remotes")?;
    Ok(Policy {
        root: root.to_path_buf(),
        endpoints,
        hosts,
        users: users.users,
        require_ssh_admin_access: users.require_ssh_admin_access,
        provisioners,
        user_clients,
        user_remotes,
        revoked_ssh_keys: Vec::new(),
    })
}

fn read_array<T>(path: impl AsRef<Path>, table: &str) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let path = path.as_ref();
    let mut document = read_toml(path)?;
    let object = document.as_table_mut().ok_or_else(|| Error::Parse {
        path: path.to_path_buf(),
        line: 1,
        message: "policy document must be a TOML table".to_owned(),
    })?;
    if object.len() != 1 || !object.contains_key(table) {
        return Err(Error::Parse {
            path: path.to_path_buf(),
            line: 1,
            message: format!("policy document must contain only [[{table}]] entries"),
        });
    }
    object
        .remove(table)
        .expect("table exists")
        .try_into()
        .map_err(|source| Error::Toml {
            path: path.to_path_buf(),
            source,
        })
}

fn read_document<T>(path: impl AsRef<Path>) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    read_typed_document(path)
}
