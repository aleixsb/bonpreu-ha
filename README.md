# Bonpreu Home Assistant Integration

Custom HACS integration for Bonpreu online shopping.

Project repository: https://github.com/aleixsb/bonpreu-ha

This project uses the same mobile API flow used by the Android app:

- OAuth-assisted login (you authenticate in Bonpreu web)
- Token exchange with `code` + `redirect_uri`
- Automatic token refresh with device token

## Current scope (MVP)

- Login and session refresh
- Read basket totals, product lines, units, and amount remaining to free delivery (when available)
- Read shopping lists and previews
- Read recent orders and active-order count
- Read regular products count and previews for quick add
- Services to:
  - add product to basket (`add_to_cart`)
  - set exact product quantity (`set_cart_quantity`)
  - remove product from basket (`remove_from_cart`)
  - add a regular product to basket by ID/name (`add_regular_to_cart`)
  - add a regular product by exact ID (`add_regular_by_id_to_cart`)
  - add shopping list to basket
  - create/rename/delete shopping list

## Exposed entities

- Cart Total
- Amount To Free Delivery
- Cart Product Lines
- Cart Units
- Shopping Lists
- Recent Orders
- Orders Waiting Shipment
- Active Orders
- Regular Products

## Exposed to-do lists

- Cart Items (supports create/update/delete)
- Regular Products (mark as completed to quick-add to cart)
- Orders Waiting Shipment (read-only)

For cart todo updates, setting item status to completed removes that product from the cart.
For regular-products todo updates, setting item status to completed adds that product to the cart.

Count sensors include preview attributes (cart lines, shopping lists, recent orders, regular products) to support dashboard cards and automations.

## Installation

### HACS

[![Open your Home Assistant instance and show the Bonpreu repository in the HACS store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=aleixsb&repository=bonpreu-ha&category=integration)

1. Open the button above.
2. Select **Download** in HACS.
3. Restart Home Assistant.
4. Add the **Bonpreu** integration from Settings → Devices & services.

### Manual Installation

Copy the `custom_components/bonpreu` directory into your Home Assistant `config/custom_components` directory, restart Home Assistant, and add **Bonpreu** from Settings → Devices & services.

### Cards

The companion dashboard cards are published separately:

[![Open Bonpreu Cards in HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=aleixsb&repository=bonpreu-cards&category=dashboard)

## Optional YAML credentials (recommended)

To automate login and reauthentication, configure Bonpreu credentials in YAML using Home Assistant secrets.

Credential behavior:

- Credentials are read from YAML on Home Assistant startup.
- The integration uses them only for the login form step.
- OTP/email-code verification can still be requested by Bonpreu and is shown in the config flow.
- If automated login is unavailable (captcha/challenge/flow changes), the integration falls back to manual callback mode.

`secrets.yaml`:

```yaml
bonpreu_username: your_email@example.com
bonpreu_password: your_password
```

`configuration.yaml`:

```yaml
bonpreu:
  username: !secret bonpreu_username
  password: !secret bonpreu_password
```

After changing YAML or secrets, restart Home Assistant.

## Login flow

### Automated flow (when YAML credentials are configured)

1. Add the integration from Settings -> Devices & services.
2. Integration starts login automatically using configured credentials.
3. Enter the email verification code when prompted.
4. Setup finishes without manual callback copy.

### Manual fallback flow

If automated login is unavailable (captcha/challenge/form changes), use manual callback mode:

1. Integration shows an authorization URL.
2. Open it in browser and log in with your Bonpreu account.
3. Copy the full URL from the browser address bar.
4. Paste that URL in the integration form to finish setup.

Accepted callback formats:

- `https://www.compraonline.bonpreuesclat.cat/sso-login?...`
- `bonpreu-atm://login?...`

Authorization codes are one-time use. If token exchange fails, run login again and use a fresh callback URL.

## Notes

- This API is private and undocumented; endpoints can change without notice.
- Do not share callback URLs: they contain short-lived login credentials.
- Do not store Bonpreu credentials directly in `configuration.yaml`; use `!secret` references.
- Endpoint failures are handled independently; sensors expose a `stale` attribute when an endpoint refresh fails and previous data is being reused.

## Local development workflow (without HACS)

For auth and catalog iteration outside Home Assistant, use the local probes in `tools/`.

Auth probe (OTP-capable, persisted transactions):

```bash
python3 tools/bonpreu_auth_probe.py credentials store --username "you@example.com" --password "your-password"
python3 tools/bonpreu_auth_probe.py start
python3 tools/bonpreu_auth_probe.py resume --transaction-id "<id>" --otp "123456"
```

Catalog probe (reuses local session, includes auth verify/search/product detail):

```bash
python3 tools/bonpreu_catalog_probe.py auth login
python3 tools/bonpreu_catalog_probe.py auth status
python3 tools/bonpreu_catalog_probe.py auth verify
python3 tools/bonpreu_catalog_probe.py catalog search "llet" --max-page-size 30
python3 tools/bonpreu_catalog_probe.py catalog product "<retailer_product_id>"
```

Both tools store local state under `~/.bonpreu-auth-probe/` with private permissions.
