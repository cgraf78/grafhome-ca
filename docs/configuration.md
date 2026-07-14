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
: Preferred absolute path to the `step` client binary. If it is absent,
  `grafhome-ca` checks `/usr/local/bin/step`, `/usr/bin/step`, and `PATH`. The
  selected executable must be owned by root or the invoking user and must not
  be group- or world-writable. When invoked as root, the executable and every
  parent directory must be root-owned and not group- or world-writable. On
  macOS, install `step` with
  Homebrew as a normal user and copy it into `/usr/local/bin/step` with root
  ownership for privileged host operations; never run Homebrew as root.

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
: Absolute path to the root-readable intermediate CA key password file. The
  file path is non-secret; the password file content must never be committed.
  This path must be inside `GRAFHOME_CA_STATE_DIR` so the `step-ca` service user
  can traverse its parent directories.

Enrollment provisioner credentials are derived rather than configured. For an
enrollment provisioner named `<name>`, the CA origin stores
`${GRAFHOME_CA_STATE_DIR}/secrets/provisioners/<name>.pub.json`,
`<name>.priv.json`, and `<name>.password`. The private JWK and password must be
owner-only regular files, and the enrollment password must differ from
`GRAFHOME_CA_PASSWORD_FILE`. `grafhome-ca migrate enrollment-provisioner-keys`
creates this layout for an existing CA without changing provisioner identities.
Upgrade every policy-consuming binary before distributing policy with the new
renewal, effectively-infinite, or SSH-administrator fields; older binaries
reject unknown policy fields. New binaries continue to accept the previous
policy shape.

`GRAFHOME_CA_SERVICE_USER`
: Unix service account and primary service group that run the CA server.

`GRAFHOME_CA_APACHE_CONF_AVAILABLE`
: Apache `conf-available` directory used by reverse-proxy templates.

## Policy Terms

Policy lives in typed TOML documents under `policy/`. Each file contains an
array of tables named after the file with hyphens replaced by underscores. For
example, `policy/user-remotes.toml` contains `[[user_remotes]]` entries.
`users.toml` may additionally carry the file-level
`require_ssh_admin_access` safety switch. TOML comments are supported,
booleans are written as `true` or `false`, endpoint ports are integers, and
host principals are arrays:

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

`users.toml` may set `require_ssh_admin_access = true` as a durable site safety
switch and designate one or more active users with `ssh_admin = true`. Once
enabled, every host with `ssh_server = true` must retain an active
`user-remotes.toml` login mapping for at least one active SSH administrator.
The separate switch ensures that accidentally deleting every designation is an
error rather than silently disabling the invariant. Policies that omit both
fields retain their existing behavior. The designation does not grant Unix or
sudo privileges; it identifies certificate users whose existing login mappings
serve as the site's administrative recovery path.

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

The renderer also derives authority-wide SSH allow-lists directly from active
`users.principal` values and every `hosts.principals` value. These are generated
template variables rather than deployment settings. The CA rejects SSH user or
host principals outside those policy-owned sets even if a provisioner token or
template is misconfigured.

`GRAFHOME_CA_PROVISIONERS_JSON`
: Template variable derived from active rows in `policy/provisioners.toml`.
  JWK rows render as whole-object runtime placeholders until a deployment step
  replaces them with complete Smallstep provisioner objects containing the
  public `key`, claims, and issuance templates. Private enrollment keys remain
  in the server-local provisioner directory and `encryptedKey` is omitted.
  Non-secret provisioner types that do not require generated key material
  render directly.
  The supported first-bootstrap path is `materialize`: it
  copies public bootstrap state from the live `step ca init` output, loads other
  public JWK files from a private operator directory, and reapplies
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

`default_ttl`, `max_ttl`, `renewal_default_ttl`, `renewal_max_ttl`, and `cert_ttl`
: Step duration strings rendered into `ca.json` or used for enrollment. Use
  Go-style `s`, `m`, or `h` units such as `24h`, `168h`, or `720h`; do not use `d`.
  `max_ttl` may be `unlimited` only for the `user_enrollment` provisioner.
  Smallstep requires a positive finite maximum, so Grafhome renders this as
  `2562047h`, the largest whole-hour Go duration (roughly 292 years). The
  configured user `cert_ttl` remains the default lifetime for normal issuance.
  Device-bound renewal provisioners use the finite `renewal_*` values instead
  of inheriting an unlimited enrollment maximum. Older policy files remain
  readable: an omitted renewal default uses `default_ttl`; when the old
  enrollment maximum is unlimited, the omitted renewal maximum becomes the
  largest finite active-user `cert_ttl` or renewal default. This preserves
  previously valid finite lifetimes without letting inactive historical rows
  inflate routine renewal authority.

`allow_effectively_infinite_cert`
: Optional `user-clients.toml` boolean, defaulting to `false`. When true on the
  exact active user/client-host row, a root operator may use `approve user
  --effectively-infinite`. The flag and allow-list entry are both required;
  routine renewal remains finite. Upgrade the target client before issuing this
  exceptional grant. It uses enrollment document version 2 so older clients
  reject it before issuance; ordinary grants remain version 1.
