"""Constants for Bonpreu integration."""

from __future__ import annotations

from datetime import timedelta
from typing import Final

DOMAIN: Final = "bonpreu"

BASE_URL: Final = "https://api.bpe.osp.tech/rocket-osp/"
REDIRECT_URI: Final = "bonpreu-atm://login"

# Extracted from app production server config.
API_KEY: Final = "su95KBXYOL67yMpPxwNH8Eu4iGLk4TT235I5P8S7"
BANNER_ID: Final = "dcbcfd72-cf23-44a2-8e14-8a38edd645a3"

HEADER_ACCEPT: Final = "application/json,*/*"
HEADER_SOURCE: Final = "android"
HEADER_SOURCE_VERSION: Final = "home-assistant"

DEFAULT_UPDATE_INTERVAL = timedelta(minutes=5)
DEFAULT_TIMEOUT_SECONDS: Final = 20

CONF_CALLBACK_URL: Final = "callback_url"
CONF_USE_ALTERNATIVE_MOBILE: Final = "use_alternative_mobile"
CONF_USE_MOBILE_REDIRECT: Final = "use_mobile_redirect"
CONF_REDIRECT_URI: Final = "redirect_uri"
CONF_DEVICE_ID: Final = "device_id"
CONF_DEVICE_TOKEN: Final = "device_token"
CONF_ACCESS_TOKEN: Final = "access_token"
CONF_REFRESH_TOKEN: Final = "refresh_token"
CONF_UPDATE_INTERVAL_MINUTES: Final = "update_interval_minutes"
CONF_ENABLE_CHECKOUT: Final = "enable_checkout"

DEFAULT_ENABLE_CHECKOUT: Final = False

SERVICE_ADD_TO_CART: Final = "add_to_cart"
SERVICE_SET_CART_QUANTITY: Final = "set_cart_quantity"
SERVICE_REMOVE_FROM_CART: Final = "remove_from_cart"
SERVICE_ADD_REGULAR_TO_CART: Final = "add_regular_to_cart"
SERVICE_ADD_REGULAR_BY_ID_TO_CART: Final = "add_regular_by_id_to_cart"
SERVICE_ADD_SHOPPING_LIST_TO_CART: Final = "add_shopping_list_to_cart"
SERVICE_CREATE_SHOPPING_LIST: Final = "create_shopping_list"
SERVICE_RENAME_SHOPPING_LIST: Final = "rename_shopping_list"
SERVICE_DELETE_SHOPPING_LIST: Final = "delete_shopping_list"

ATTR_ENTRY_ID: Final = "entry_id"
ATTR_RETAILER_PRODUCT_ID: Final = "retailer_product_id"
ATTR_DELTA: Final = "delta"
ATTR_TARGET_QUANTITY: Final = "target_quantity"
ATTR_QUANTITY: Final = "quantity"
ATTR_QUERY: Final = "query"
ATTR_LIST_ID: Final = "list_id"
ATTR_LIST_NAME: Final = "list_name"
ATTR_PRODUCTS: Final = "products"
