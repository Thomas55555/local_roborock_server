# Custom certificate management

Use this if you do not want Cloudflare DNS-01 automation and instead want to provide the TLS certificate files yourself during [Installation](installation.md).

## Required Config

Set the TLS section in `config.toml` to the provided-certificate mode:

```toml
[tls]
mode = "provided"
cert_file = "/data/certs/fullchain.pem"
key_file = "/data/certs/privkey.pem"
```

If you use the setup wizard and answer no to Cloudflare, it will write these values for you. You then need to place your certificate files at `data/certs/fullchain.pem` and `data/certs/privkey.pem` before starting the stack.

## Related Docs

- [Installation](installation.md)
- [Cloudflare setup](cloudflare_setup.md)
- [Onboarding](onboarding.md)
