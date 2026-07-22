"""Async Bonpreu API client."""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.parse
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp

from ..const import (
    API_KEY,
    BANNER_ID,
    BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    HEADER_ACCEPT,
    HEADER_SOURCE,
    HEADER_SOURCE_VERSION,
)
from .auth import format_auth_header_value
from .exceptions import BonpreuApiError, BonpreuAuthError
from .models import OAuthUris, TokenPair

_LOGGER = logging.getLogger(__name__)


class BonpreuApiClient:
    """API client for Bonpreu mobile endpoints."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        language: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        device_token: str | None = None,
        retailer_region_id: str | None = None,
        on_token_refresh: Callable[[str, str | None], Awaitable[None]] | None = None,
    ) -> None:
        self._session = session
        self._language = normalize_api_language(language)
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._device_token = device_token
        self._retailer_region_id = retailer_region_id
        self._on_token_refresh = on_token_refresh
        self._refresh_lock = asyncio.Lock()

    @property
    def access_token(self) -> str | None:
        return self._access_token

    @property
    def refresh_token(self) -> str | None:
        return self._refresh_token

    @property
    def device_token(self) -> str | None:
        return self._device_token

    def set_tokens(self, *, access_token: str, refresh_token: str | None) -> None:
        """Set current access and refresh token."""
        self._access_token = access_token
        self._refresh_token = refresh_token

    def set_device_token(self, token: str | None) -> None:
        """Set current device token."""
        self._device_token = token

    def _base_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": HEADER_ACCEPT,
            "x-api-key": API_KEY,
            "BannerId": BANNER_ID,
            "Accept-Language": self._language,
            "Ecom-Request-Source": HEADER_SOURCE,
            "Ecom-Request-Source-Version": HEADER_SOURCE_VERSION,
        }
        if self._retailer_region_id:
            headers["RetailerRegionId"] = self._retailer_region_id
        return headers

    def _device_auth_headers(self) -> dict[str, str]:
        """Return auth header using current device token."""
        if not self._device_token:
            raise BonpreuAuthError("Device token missing.")
        return {"Authorization": format_auth_header_value(self._device_token)}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        require_auth: bool = True,
        allow_refresh: bool = True,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Any:
        url = f"{BASE_URL}{path}"
        request_headers = self._base_headers()
        if headers:
            request_headers.update(headers)

        request_access_token: str | None = None

        if require_auth:
            if not self._access_token:
                raise BonpreuAuthError("Access token missing.")
            request_access_token = self._access_token
            request_headers["Authorization"] = format_auth_header_value(self._access_token)

        timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT_SECONDS)

        try:
            async with self._session.request(
                method,
                url,
                headers=request_headers,
                timeout=timeout,
                **kwargs,
            ) as response:
                if response.status == 401 and require_auth and allow_refresh:
                    await response.read()
                    if await self._refresh_access_token(failed_access_token=request_access_token):
                        return await self._request(
                            method,
                            path,
                            require_auth=require_auth,
                            allow_refresh=False,
                            headers=headers,
                            **kwargs,
                        )
                    raise BonpreuAuthError("Unauthorized and token refresh failed.", status_code=401)

                if response.status >= 400:
                    body = await response.text()
                    raise BonpreuApiError(
                        _build_http_error_message(response.status, path, body),
                        status_code=response.status,
                    )

                content_type = response.headers.get("Content-Type", "")
                if _looks_json_content_type(content_type):
                    try:
                        return await response.json(content_type=None)
                    except (ValueError, json.JSONDecodeError) as err:
                        raise BonpreuApiError(f"Invalid JSON response for {path}.") from err

                text = await response.text()
                stripped = text.strip()
                if stripped.startswith("{") or stripped.startswith("["):
                    try:
                        return json.loads(stripped)
                    except (ValueError, json.JSONDecodeError):
                        pass

                return text
        except asyncio.TimeoutError as err:
            raise BonpreuApiError(f"Request timeout for {path}.") from err
        except aiohttp.ClientError as err:
            raise BonpreuApiError(f"Request failed for {path}: {err.__class__.__name__}.") from err

    async def _refresh_access_token(self, *, failed_access_token: str | None = None) -> bool:
        """Refresh access token using refresh token and device token."""
        if not self._refresh_token or not self._device_token:
            return False

        async with self._refresh_lock:
            if (
                failed_access_token
                and self._access_token
                and self._access_token != failed_access_token
            ):
                return True

            # Another coroutine may have refreshed already.
            if not self._refresh_token or not self._device_token:
                return False

            headers = {
                "Authorization": format_auth_header_value(self._device_token),
            }
            payload = {"refreshToken": self._refresh_token}

            try:
                data = await self._request(
                    "POST",
                    "v1/authorize/refresh",
                    require_auth=False,
                    allow_refresh=False,
                    headers=headers,
                    json=payload,
                )
            except BonpreuApiError as err:
                _LOGGER.warning("Token refresh failed: %s", err)
                return False

            access = data.get("token")
            refresh = data.get("refreshToken") or self._refresh_token
            if not access:
                return False

            self._access_token = access
            self._refresh_token = refresh
            if self._on_token_refresh:
                await self._on_token_refresh(access, refresh)
            return True

    async def get_oauth_uris(self, *, use_alternative_mobile: bool = False) -> OAuthUris:
        """Get OAuth URI endpoints."""
        path = "v1/authorize/uris/alternative-mobile" if use_alternative_mobile else "v1/authorize/uris"
        data = await self._request(
            "GET",
            path,
            require_auth=False,
            headers=self._device_auth_headers(),
        )
        return OAuthUris(
            authentication_uri=data["authenticationUri"],
            reauthentication_uri=data["reauthenticationUri"],
            registration_uri=data["registrationUri"],
            state=data["state"],
        )

    async def exchange_authorization_code(self, code: str, redirect_uri: str) -> TokenPair:
        """Exchange OAuth authorization code for access/refresh token."""
        if not self._device_token:
            raise BonpreuAuthError("Device token missing.")

        payload = {
            "authorizationCode": code,
            "redirectUri": redirect_uri,
        }
        auth_candidates = [
            format_auth_header_value(self._device_token),
            f"token:{self._device_token}",
        ]
        unique_auth_candidates = list(dict.fromkeys(auth_candidates))

        data: dict[str, Any] | None = None
        last_error: BonpreuApiError | None = None
        for auth_header in unique_auth_candidates:
            try:
                candidate = await self._request(
                    "POST",
                    "v1/authorize",
                    require_auth=False,
                    headers={"Authorization": auth_header},
                    json=payload,
                )
            except BonpreuApiError as err:
                last_error = err
                continue

            if not isinstance(candidate, dict):
                raise BonpreuApiError("Invalid JSON response for v1/authorize.")
            data = candidate
            break

        if data is None:
            if last_error is not None:
                raise last_error
            raise BonpreuApiError("Token exchange failed for v1/authorize.")

        access_token = str(data.get("token") or "").strip()
        if not access_token:
            raise BonpreuApiError("Token exchange did not return access token.")

        refresh_token = str(data.get("refreshToken") or "").strip() or None
        return TokenPair(access_token=access_token, refresh_token=refresh_token)

    async def get_device_token(self, device_id: str) -> str | None:
        """Get API device token for a generated device ID."""
        data = await self._request(
            "GET",
            f"v1/mobileDevice/{device_id}",
            require_auth=False,
            headers={"Authorization": ""},
        )
        return data.get("token")

    async def register_device(self, device_id: str, device_model: str = "Home Assistant") -> None:
        """Register or update the device model."""
        await self._request(
            "PUT",
            f"v1/mobileDevice/{device_id}",
            require_auth=False,
            headers={"Authorization": ""},
            data={"deviceModel": device_model},
        )

    async def ensure_device_token(self, device_id: str) -> str:
        """Ensure a valid device token exists."""
        token: str | None = None
        try:
            token = await self.get_device_token(device_id)
        except BonpreuApiError as err:
            # Expected for first run with a brand-new generated device id.
            if err.status_code != 404:
                raise

        if token:
            self._device_token = token
            return token

        await self.register_device(device_id)

        # Backend can be eventually consistent right after registration.
        for attempt in range(5):
            try:
                token = await self.get_device_token(device_id)
            except BonpreuApiError as err:
                if err.status_code != 404:
                    raise
                token = None
            if token:
                break
            await asyncio.sleep(0.4 * (attempt + 1))

        if not token:
            raise BonpreuApiError("Could not obtain device token.")

        self._device_token = token
        return token

    async def get_cart_active(self) -> dict[str, Any]:
        """Get active basket."""
        return await self._request("GET", "v1/carts/active")

    async def get_cart_view(self) -> dict[str, Any]:
        """Get active basket view (v2)."""
        return await self._request("GET", "v2/carts/active/cart-view")

    async def add_to_cart(self, retailer_product_id: str, delta: int = 1) -> dict[str, Any]:
        """Add/remove quantity for a product in active basket."""
        payload = [{"retailerProductId": retailer_product_id, "delta": delta}]
        headers = {"Analytics-Source-Id": str(uuid.uuid4())}
        return await self._request("POST", "v2/carts/active", headers=headers, json=payload)

    async def get_shopping_lists(self) -> Any:
        """Get all shopping lists."""
        return await self._request("GET", "v1/product-lists")

    async def create_shopping_list(self, list_name: str, products: list[str] | None = None) -> dict[str, Any]:
        """Create a shopping list."""
        payload = {"listName": list_name, "products": products or []}
        return await self._request("POST", "v1/product-lists", json=payload)

    async def rename_shopping_list(self, list_id: str, list_name: str) -> None:
        """Rename a shopping list."""
        await self._request("PUT", f"v1/product-lists/{list_id}", json={"listName": list_name})

    async def delete_shopping_list(self, list_id: str) -> None:
        """Delete a shopping list."""
        await self._request("DELETE", f"v1/product-lists/{list_id}")

    async def add_shopping_list_to_cart(self, list_id: str) -> dict[str, Any]:
        """Add all shopping-list products to active basket."""
        headers = {"Analytics-Source-Id": str(uuid.uuid4())}
        return await self._request(
            "POST",
            f"v1/product-lists/{list_id}/add-products-to-active-basket",
            headers=headers,
        )

    async def get_orders_recent(self) -> Any:
        """Get recent orders."""
        return await self._request("GET", "v2/orders/recent")

    async def get_orders_not_cancelled_count(self) -> Any:
        """Get not-cancelled order count."""
        return await self._request("GET", "v3/orders/not-cancelled-count")

    async def get_regulars(self, *, limit: int = 100, offset: int = 0) -> Any:
        """Get regular/frequent products."""
        return await self._request(
            "GET",
            "v3/catalog/regulars",
            params={"showProductLimit": limit, "productListOffset": offset},
        )

    async def search_products(
        self,
        *,
        query: str,
        screen_size: str = "S",
        max_products_to_decorate: int = 100,
        max_page_size: int = 100,
        include_additional_page_info: bool = True,
        sort_option_id: str | None = None,
        encoded_filters: str | None = None,
        category_id: str | None = None,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        """Search catalog products using mobile endpoint semantics."""
        query_parts: list[str] = [
            f"q={urllib.parse.quote(query, safe='')}",
            f"screenSize={urllib.parse.quote(screen_size, safe='')}",
            f"maxProductsToDecorate={max_products_to_decorate}",
            f"maxPageSize={max_page_size}",
            f"includeAdditionalPageInfo={'true' if include_additional_page_info else 'false'}",
        ]
        if sort_option_id:
            query_parts.append(f"sortOptionId={urllib.parse.quote(sort_option_id, safe='')}")
        if encoded_filters:
            query_parts.append(f"filters={encoded_filters}")
        if category_id:
            query_parts.append(f"categoryId={urllib.parse.quote(category_id, safe='')}")
        if page_token:
            query_parts.append(f"pageToken={urllib.parse.quote(page_token, safe='')}")

        data = await self._request("GET", f"v4/products/search?{'&'.join(query_parts)}")
        if not isinstance(data, dict):
            raise BonpreuApiError("Invalid search response for v4/products/search.")
        return data

    async def get_product_detail(self, retailer_product_id: str) -> dict[str, Any]:
        """Get detailed product payload for a retailer product id."""
        encoded_id = urllib.parse.quote(retailer_product_id, safe="")
        data = await self._request("GET", f"v2/products/{encoded_id}/bop")
        if not isinstance(data, dict):
            raise BonpreuApiError("Invalid product detail response for v2/products/<id>/bop.")
        return data

    async def get_user_current(self) -> dict[str, Any]:
        """Get authenticated customer profile."""
        data = await self._request("GET", "v1/user/current")
        if not isinstance(data, dict):
            raise BonpreuApiError("Invalid user profile response for v1/user/current.")
        return data

    async def get_products(self, product_ids: list[str]) -> list[dict[str, Any]]:
        """Get product details for one or more product IDs."""
        unique_ids = [
            cleaned
            for cleaned in dict.fromkeys(product_id.strip() for product_id in product_ids)
            if cleaned
        ]
        if not unique_ids:
            return []

        data = await self._request("PUT", "v1/products", json=unique_ids)
        return _parse_products_payload(data)


def _looks_json_content_type(content_type: str) -> bool:
    lowered = content_type.lower()
    return "application/json" in lowered or "+json" in lowered


def normalize_api_language(language: str | None) -> str:
    """Normalize Home Assistant language to supported Bonpreu locale."""
    if not language:
        return "ca-ES"

    normalized = language.strip().replace("_", "-").lower()
    if normalized.startswith("ca"):
        return "ca-ES"
    if normalized.startswith("es"):
        return "es-ES"
    return "ca-ES"


def _build_http_error_message(status: int, path: str, body: str) -> str:
    message = f"HTTP {status} for {path}"

    try:
        parsed = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return message

    if isinstance(parsed, dict):
        for key in ("reason", "error", "code", "message"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return f"{message}: {value.strip()}"

    return message


def _parse_products_payload(payload: Any) -> list[dict[str, Any]]:
    """Parse product list payload across known response envelopes."""
    if isinstance(payload, list):
        return [_unwrap_product_payload(item) for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    direct_products = payload.get("products")
    if isinstance(direct_products, list):
        return [_unwrap_product_payload(item) for item in direct_products if isinstance(item, dict)]

    product_groups = payload.get("productGroups")
    if isinstance(product_groups, list):
        flattened: list[dict[str, Any]] = []
        for group in product_groups:
            if not isinstance(group, dict):
                continue
            for key in ("products", "decoratedProducts"):
                values = group.get(key)
                if isinstance(values, list):
                    flattened.extend(_unwrap_product_payload(item) for item in values if isinstance(item, dict))
        if flattened:
            return flattened

    for key in ("items", "data", "content"):
        values = payload.get(key)
        if isinstance(values, list):
            return [_unwrap_product_payload(item) for item in values if isinstance(item, dict)]

    return []


def _unwrap_product_payload(product: dict[str, Any]) -> dict[str, Any]:
    nested = product.get("product")
    if not isinstance(nested, dict):
        return product

    merged = dict(nested)
    for key in ("productId", "retailerProductId", "id", "sku"):
        if merged.get(key):
            continue
        value = product.get(key)
        if value is not None:
            merged[key] = value
    return merged
