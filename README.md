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

## Login flow

1. Integration gives you an authorization URL.
2. Open it in browser and log in with your Bonpreu account.
3. After login, copy the full URL from the browser address bar.
4. Paste that URL in the integration form to finish setup.

Accepted callback formats:

- `https://www.compraonline.bonpreuesclat.cat/sso-login?...`
- `bonpreu-atm://login?...`

Authorization codes are one-time use. If token exchange fails, run login again and use a fresh callback URL.

## Notes

- This API is private and undocumented; endpoints can change without notice.
- Do not share callback URLs: they contain short-lived login credentials.
- Endpoint failures are handled independently; sensors expose a `stale` attribute when an endpoint refresh fails and previous data is being reused.
