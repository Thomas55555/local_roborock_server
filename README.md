# Roborock Local Server

If this project helps, you can support it or next time you buy a Roborock device, come back here and use my affiliate links!

[![Buy Me a Coffee][badge-bmac]][link-bmac]
[![PayPal][badge-paypal]][link-paypal]
[![Roborock 5 Off][badge-roborock-discount]][link-roborock-discount]
[![Roborock Affiliate][badge-roborock-affiliate]][link-roborock-affiliate]
[![Amazon Affiliate][badge-amazon]][link-amazon]

Roborock Local Server is a private Roborock HTTPS and MQTT stack you run on your own system.

This service is meant to stay private. Point your own DNS at your server's LAN IP and do **NOT** expose it directly to the public internet. In its current state it does not handle internet exposure safely enough. For now, keep it on your LAN only. In the future, I plan to reuse Roborock's auth natively which should make everything secure enough.

This project is in VERY EARLY BETA!!! Do not use this repository unless you are sure you know what you are doing and are rather technical.

## Requirements

- Docker with `docker compose`
- `uv`
- a Linux server or Linux VM on your LAN
- a domain you control
- a Cloudflare API token with DNS edit access for the zone

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

## How It Works

Pick one hostname under your domain, for example `roborock.example.com`.

- `stack_fqdn` is the hostname the app, vacuums, and admin UI will use.
- `base_domain` is the zone used for the wildcard certificate, for example `example.com`.
- Your network's DNS should point `stack_fqdn` at your server's LAN IP.
- Cloudflare is only used for DNS-01 certificate issuance. It does not need to proxy traffic to your server.

The vacuum needs to be able to hit your server on ports 443/tcp and 8883/tcp.
If you use iPhone MITM intercept, expose 8081/tcp for the mitmweb UI (logs + WireGuard QR).
When running in Docker, prefer the Admin "Open WireGuard Config (Docker-safe)" link over mitmweb's QR if the QR shows a container-only endpoint.
The Admin MITM panel also provides an "Open WireGuard QR" code generated from the Docker-safe config.

- `443/tcp` for HTTPS
- `8883/tcp` for MQTT over TLS
- `8081/tcp` for mitmweb (optional, MITM only, access by IP not hostname)
- `51820/udp` for WireGuard MITM tunnel traffic

## Project Layout

After setup, the folder should look like this:

```text
roborock_local_server/
  compose.yaml
  config.toml
  secrets/
    cloudflare_token
  data/
```

## Setup

1. Change into the project folder.

```bash
cd roborock_local_server
```

2. Install the local project environment.

```bash
uv sync
```

3. Generate an admin password hash.

```bash
uv run roborock-local-server hash-password
```

4. Generate an admin session secret.

```bash
uv run roborock-local-server generate-secret
```

Both commands print a single value to your terminal and do not save it to a file for you.

- `hash-password` prints the value you should paste into `admin.password_hash`
- `generate-secret` prints the value you should paste into `admin.session_secret`
- if you did not save the output earlier, just run the command again and use the new value
- if you change `session_secret` later, existing admin login sessions will be invalidated

5. Create the secrets folder and save your Cloudflare API token.

```bash
mkdir -p secrets
printf '%s' 'YOUR_CLOUDFLARE_TOKEN' > secrets/cloudflare_token
chmod 600 secrets/cloudflare_token
```

6. Create `config.toml` with this baseline configuration.

```toml
[network]
# The hostname your vacuum and admin UI will connect to.
# Set this to the private DNS name you created for this server.
stack_fqdn = "roborock.example.com"

# The address the container listens on internally.
# Leave this at 0.0.0.0 unless you know you need something else.
bind_host = "0.0.0.0"

# HTTPS port exposed by the server.
# Leave this at 443 unless you are intentionally using a different port.
https_port = 443

# MQTT-over-TLS port exposed by the server.
# Leave this at 8883 unless you are intentionally using a different port.
mqtt_tls_port = 8883

# Roborock region code.
# Use your actual Roborock region. (us, eu, ru, cn)
region = "us"

[broker]
# Use "embedded" to run Mosquitto inside the container.
# Use "external" only if you already have your own MQTT broker.
mode = "embedded"

# MQTT broker host the TLS proxy forwards to.
# For embedded mode, leave this as 127.0.0.1.
host = "127.0.0.1"

# MQTT broker port the TLS proxy forwards to.
# For embedded mode, leave this at 18830.
port = 18830

# Name or path of the Mosquitto binary inside the container.
# Leave this as "mosquitto" unless you are deliberately changing the image.
mosquitto_binary = "mosquitto"

# Keeps the rr/m and rr/d topics synchronized for the stack.
# Leave this enabled unless you have a specific reason to disable it.
enable_topic_bridge = true

[storage]
# Where the container stores persistent data.
# Leave this as /data to match the Docker volume mount.
data_dir = "/data"

[tls]
# "cloudflare_acme" automatically issues and renews a wildcard cert through Cloudflare DNS-01.
# "provided" means you will supply your own cert and key files.
mode = "cloudflare_acme"

# The DNS zone used for the wildcard certificate.
# Example: if stack_fqdn is roborock.example.com, set this to example.com.
base_domain = "example.com"

# Email address used with the ACME certificate account.
# Set this to your email address.
email = "you@example.com"

# Path inside the container to the Cloudflare token file.
# Leave this as-is if you are using the included compose file.
cloudflare_token_file = "/run/secrets/cloudflare_token"

# Renew when the certificate has this many days or less left.
# 30 is a good default.
renew_days_before = 30

# How often, in seconds, the app checks whether a renewal is needed.
# 43200 = every 12 hours.
renew_check_seconds = 43200

# ACME provider profile used by acme.sh.
# Leave this at zerossl unless you are intentionally changing providers.
acme_server = "zerossl"

[admin]
# Paste the exact terminal output from:
# uv run roborock-local-server hash-password
# This value is not saved anywhere automatically by the tool.
password_hash = "PASTE_THE_HASH_FROM_HASH_PASSWORD"

# Paste the exact terminal output from:
# uv run roborock-local-server generate-secret
# This value is not saved anywhere automatically by the tool.
# This should be long, random, and kept private.
session_secret = "PASTE_THE_SECRET_FROM_GENERATE_SECRET"

# How long an admin login session lasts, in seconds.
# 86400 = 24 hours.
session_ttl_seconds = 86400
```

7. In your private DNS, point `roborock.example.com` to your server's LAN IP.

8. Start the stack.

```bash
docker compose up --build -d
```

9. Open `https://roborock.example.com/admin` from a device on the same LAN.

10. Sign in and use the Cloud Import section to request an email code and import your Roborock cloud data.

## External MQTT

If you want to use your own broker instead of the embedded Mosquitto instance, replace the `[broker]` section with this:

```toml
[broker]
# Use your existing broker instead of the embedded one.
mode = "external"

# IP or hostname of your MQTT broker on your LAN.
host = "10.0.0.20"

# Port of your existing MQTT broker.
port = 1883

# Still leave this as mosquitto; it is ignored in external mode.
mosquitto_binary = "mosquitto"

# Keep this enabled unless you know you do not want topic bridging.
enable_topic_bridge = true
```

## Using Your Own Certificate

If you already have a certificate and key, replace the `[tls]` section with this:

```toml
[tls]
# Use this when you are providing your own certificate files.
mode = "provided"

# Not used in provided mode. Leave blank.
base_domain = ""

# Not used in provided mode. Leave blank.
email = ""

# Not used in provided mode. Leave blank.
cloudflare_token_file = ""

# Still used to decide when to check cert freshness.
# Fine to leave at 30.
renew_days_before = 30

# Still used for the renewal check loop timing.
# Fine to leave at 43200.
renew_check_seconds = 43200

# Not used in provided mode by the running service, but safe to leave as-is.
acme_server = "zerossl"

# Path inside the container to your certificate full chain PEM file.
# Put this file in data/certs/fullchain.pem unless you have a reason not to.
cert_file = "/data/certs/fullchain.pem"

# Path inside the container to your private key PEM file.
# Put this file in data/certs/privkey.pem unless you have a reason not to.
key_file = "/data/certs/privkey.pem"
```

Put those files in the mounted `data/certs/` directory before starting the stack, and make sure the files are readable by Docker on your Linux host.

## What the Admin UI Does

The admin UI is intentionally small:

- sign in and sign out
- show service health
- show known vacuums
- import cloud data with email-code login
- show built-in support links for the project

## Persistent Data

The container writes everything under `data/`:

- `data/certs/`: live certificate material
- `data/acme/`: ACME client state
- `data/runtime/web_api_inventory.json`: normalized cloud inventory
- `data/runtime/web_api_inventory_full_snapshot.json`: raw cloud snapshot with secrets, keep private
- `data/runtime/runtime_credentials.json`: generated runtime credentials and local keys
- `data/state/device_key_state.json`: device key recovery state
- `data/runtime/*.log` and `data/runtime/*.jsonl`: operational logs

## Cloudflare Token Permissions

Use a token scoped only to the zone in `tls.base_domain`.

The recommended Cloudflare setup is:

- token type: user API token
- template: `Edit Zone DNS`
- zone scope: only the single zone used by this project

Cloudflare's current token creation docs:

- https://developers.cloudflare.com/fundamentals/api/get-started/create-token/
- https://developers.cloudflare.com/fundamentals/api/reference/template/

## Daily Operation

Once the stack is up:

- leave the container running
- keep your private DNS pointed at the server
- renewals happen automatically
- use `/admin` to verify health and connected vacuums

## Updating

Pull the latest project changes, then rebuild and restart:

```bash
docker compose up --build -d
```

## Sanity Check

A healthy first run looks like this:

- `https://<stack_fqdn>/admin` loads
- the container stays up
- certificates are present under `data/certs/`
- cloud import succeeds
- `/admin` shows the HTTPS server, MQTT TLS proxy, and broker as healthy

[link-bmac]: https://buymeacoffee.com/lashl
[badge-bmac]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-yellow?style=for-the-badge&logo=buymeacoffee&logoColor=black
[link-paypal]: https://paypal.me/LLashley304
[badge-paypal]: https://img.shields.io/badge/PayPal-donate-00457C?style=for-the-badge&logo=paypal&logoColor=white
[link-roborock-discount]: https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3DEQe6p1jdZczHEN4Q0nbsG9sZRm0RK1gW5eSM%252FCzcW4Q%253D
[badge-roborock-discount]: https://img.shields.io/badge/Roborock-5%25%20Off-C00000?style=for-the-badge
[link-roborock-affiliate]: https://roborock.pxf.io/B0VYV9
[badge-roborock-affiliate]: https://img.shields.io/badge/Roborock-affiliate-B22222?style=for-the-badge
[link-amazon]: https://amzn.to/4bGfG6B
[badge-amazon]: https://img.shields.io/badge/Amazon-affiliate-FF9900?style=for-the-badge&logo=amazon&logoColor=white
