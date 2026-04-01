# Cloudflare setup

Use this optional guide if you want Cloudflare DNS-01 certificate issuance and automatic renewal during [Installation](installation.md). If you would rather provide your own certificate files, see [Custom certificate management](custom_cert_management.md).

Cloudflare is used to get the certificates for your domain so that when we run the server, the vacuum will trust the domain. This also lets the server renew the certificate automatically so you do not have to rotate it by hand when it expires.

## Create the Cloudflare Token

Create a user API token in Cloudflare for the zone you will use in `tls.base_domain`.

1. Sign in to the Cloudflare dashboard.
2. Open `My Profile` -> `API Tokens`.
3. Select `Create Token`.
4. Start from the `Edit Zone DNS` template.
5. Give the token a clear name such as `roborock-local-server-example-com`.
6. Scope the token to only the zone you will use for this project.
7. Review the summary and create the token.
8. Copy the token secret immediately. Cloudflare only shows it once.

For this project, keep the token limited to the single zone you are using. Do not use a global API key.

## Related Docs

- [Installation](installation.md)
- [Custom certificate management](custom_cert_management.md)
- [Onboarding](onboarding.md)
