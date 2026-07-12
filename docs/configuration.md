# Configuration Reference

All deployment constants use the `GRAFHOME_CA_` prefix. Real deployment config
belongs under `${XDG_CONFIG_HOME:-~/.config}/grafhome-ca/config/deployment.env`
in private site configuration. Derived values are computed by code instead of
being stored independently.

## `config/deployment.env`

This file uses literal `KEY=value` lines. It is not shell-sourced; do not quote
values.

Most values are target-host runtime paths. Keys whose names include `ROOT` or
refer to the `grafhome-ca` helper are command-runner paths for root/admin
rollout steps, because live initialization, reconciliation, renewal, and export
plans run with root privileges on the target host. On shdeps-managed hosts where
root uses dotfiles, those tool paths normally live under `/root/.local/bin`.

`GRAFHOME_CA_STATE_DIR`
: Root directory for CA-owned mutable state on the CA host.

`GRAFHOME_CA_SERVER_STEPPATH`
: Root-owned `step` client state for managing the CA from the CA host.

`GRAFHOME_CA_USER_STEPPATH`
: Relative path under a user's home directory for user-level `step` state.

`GRAFHOME_CA_SSH_TRUST_DIR`
: Directory for generated trusted CA public key material.

`GRAFHOME_CA_AUTH_PRINCIPALS_DIR`
: Directory used by `AuthorizedPrincipalsFile` snippets.

`GRAFHOME_CA_PROXY_TLS_DIR`
: Directory for proxy TLS files when rendered for Apache. Proxy certificate
  plans install the exported `root_ca.crt` here so Apache can verify the HTTPS
  CA origin before proxying.

`GRAFHOME_CA_PROXY_ACME_WEBROOT`
: Absolute path to the webroot directory used by `step ca certificate
  --webroot` for proxy X.509 certificate issuance and renewal. The proxy web
  server must serve `${GRAFHOME_CA_PROXY_ACME_WEBROOT}/.well-known/acme-challenge/`
  over HTTP for the `ca_api` DNS name without requiring authentication.

`GRAFHOME_CA_STEP_CA_BIN`
: Absolute path to the `step-ca` server binary.

`GRAFHOME_CA_ROOT_STEP_BIN`
: Absolute path to the root-owned `step` client binary.

`GRAFHOME_CA_HELPER_BIN`
: Absolute path where the root-run `grafhome-ca` helper is installed. For
  shdeps-managed hosts where root also uses dotfiles, this is normally
  `/root/.local/bin/grafhome-ca`.

`GRAFHOME_CA_HOST_KEY_PATH`
: Absolute path to the SSH host private key used by host certificate renewal.
  The certificate path is derived as `<GRAFHOME_CA_HOST_KEY_PATH>-cert.pub`.
  Rendered sshd fragments reference that derived host certificate path with
  `HostCertificate`.

`GRAFHOME_CA_PASSWORD_FILE`
: Absolute path to the root-readable `step-ca` key password file. The file path
  is non-secret; the password file content must never be committed. This path
  must be inside `GRAFHOME_CA_STATE_DIR` so the `step-ca` service user can
  traverse its parent directories.

`GRAFHOME_CA_SERVICE_USER`
: Unix service account and primary service group that run the CA server.

`GRAFHOME_CA_APACHE_CONF_AVAILABLE`
: Apache `conf-available` directory used by reverse-proxy templates.

## Policy Terms

Policy lives in typed TOML documents under `policy/`. Each file contains one
array of tables named after the file with hyphens replaced by underscores. For
example, `policy/user-remotes.toml` contains `[[user_remotes]]` entries. TOML
comments are supported, booleans are written as `true` or `false`, endpoint
ports are integers, and host principals are arrays:

```toml
# This host accepts and initiates certificate-authenticated SSH connections.
[[hosts]]
host = "server-a"
ssh_server = true
ssh_client = true
principals = ["server-a", "server-a.example.test"]
```

The executable policy surface contains six files:

- `endpoints.toml`: the public and origin CA endpoints
- `hosts.toml`: enrolled machines and their host certificate principals
- `users.toml`: certificate users and their certificate settings
- `provisioners.toml`: CA provisioner roles and certificate lifetimes
- `user-clients.toml`: hosts where each user may enroll and renew a certificate
- `user-remotes.toml`: remote accounts each user may access over SSH

Operational inventories such as schedulers, static keys, emergency access, and
CA operators are intentionally outside Grafhome CA policy. The CLI does not
enforce them, so keeping them beside executable authorization policy would give
a misleading impression that changing them affects the CA.

The schemas in `schemas/policy/` validate the complete TOML documents. Run
`grafhome-ca check` after editing policy; commands that mutate CA or host state
also validate policy and its filesystem provenance before proceeding.

`policy/user-remotes.toml` is the sole source of SSH login authorization. Each
active row maps one active policy user's principal to one Unix account on one
host. A user whose `status` is `planned` or `disabled` is omitted from rendered
authorized-principals files even if historical access rows remain active.

`users.principal` and `hosts.principals` directly own the user and host
certificate namespaces. `grafhome-ca check` rejects duplicate principals,
including collisions between user and host certificates.

`ca_origin`
: The private CA service endpoint hosted on the CA origin host.

`ca_api`
: The client-facing HTTPS endpoint, often reverse-proxied to the CA origin.

`GRAFHOME_CA_API_DNS_NAME`
: Template variable derived from the `ca_api` endpoint `dns_name` field.

`GRAFHOME_CA_ORIGIN_DNS_NAME`
: Template variable derived from the `ca_origin` endpoint `dns_name` field.

`GRAFHOME_CA_ORIGIN_PORT`
: Template variable derived from the `ca_origin` endpoint `port` field.

`GRAFHOME_CA_ORIGIN_ADDRESS`
: Template variable derived from the `ca_origin` endpoint `address` field. The
  step-ca listener binds to this address and port, not to all interfaces.

`GRAFHOME_CA_X509_ALLOWED_DNS_JSON`
: Template variable derived from the `ca_api` and `ca_origin` endpoint
  `dns_name` fields. It renders the authority-level X.509 DNS allow-list used
  by step-ca so the client-facing proxy name and the private backend serving
  name are both explicit issuance policy.

`GRAFHOME_CA_PROVISIONERS_JSON`
: Template variable derived from active rows in `policy/provisioners.toml`.
  JWK rows render as whole-object runtime placeholders until a deployment step
  replaces them with complete Smallstep-generated provisioner objects containing
  both the public `key` and encrypted private-key material. Non-secret
  provisioner types that do not require generated key material render directly.
  The supported first-bootstrap path is `materialize`: it
  copies the bootstrap JWK from the live `step ca init` output, loads additional
  encrypted JWK files from a private operator directory, and reapplies
  policy-derived claims before the staged `ca.json` is installed.

`GRAFHOME_CA_HOST_CERT_PATH`
: Template variable derived from `GRAFHOME_CA_HOST_KEY_PATH`. It is not stored
  in `deployment.env`.

`user_ca_keys.pem`
: Public trust file exported by `grafhome-ca export` and installed at
  `${GRAFHOME_CA_SSH_TRUST_DIR}/user_ca_keys.pem` for `TrustedUserCAKeys`.

`ssh_known_hosts`
: Public host-CA trust file exported by `grafhome-ca export` and
  installed at `${GRAFHOME_CA_SSH_TRUST_DIR}/ssh_known_hosts` for SSH clients.
  It contains `@cert-authority` entries for managed host certificate
  principals, so real exports can reveal private topology even though they do
  not contain secrets.

`root_fingerprint`
: Public SHA-256 fingerprint of the X.509 root CA certificate. Enrollment
  grants carry it as exactly 64 hexadecimal characters so `grafhome-ca` can
  bootstrap pinned trust internally. A grant's CA URL must exactly match the
  configured `ca_api` URL before bootstrap begins.

`principal`
: A name embedded in an SSH certificate and later matched by OpenSSH policy.

`default_ttl`, `max_ttl`, and `cert_ttl`
: Step duration strings rendered into `ca.json` or used for enrollment. Use
  Go-style `s`, `m`, or `h` units such as `24h`, `168h`, or `720h`; do not use `d`.
