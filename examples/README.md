# Examples

This directory contains sanitized site configuration examples. They are safe to
commit publicly and are used by the test suite to keep examples valid.

`site-config/` mirrors the runtime config root expected by `grafhome-ca`:

```text
${XDG_CONFIG_HOME:-~/.config}/grafhome-ca/
  config/deployment.env
  policy/ca.toml
  policy/users.toml
  policy/hosts/<host>.toml
```

`legacy-site-config/` preserves the previous six-file policy shape as a
migration and compatibility fixture. It is not the recommended authoring
layout for new deployments.

To adapt the example for a real deployment, copy the `site-config/` contents to
that XDG location in a private repository or private host configuration system,
then replace every example hostname, address, account, and path with site-local
values. Runtime secrets such as CA private keys, passwords, provisioner
encrypted keys, SSH private keys, and tokens still do not belong in these files.
After a real CA is initialized, `grafhome-ca export` derives rollout
inputs from the CA's public state and writes a bundle whose `manifest.json`
matches `schemas/public/export-manifest.schema.json`. Real export bundles may
include private topology in CA URLs and host principals, so they should stay in
private rollout state rather than this public repository.
