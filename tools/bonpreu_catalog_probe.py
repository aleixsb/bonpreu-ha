#!/usr/bin/env python3
"""Standalone local-first catalog probe built on the working auth probe."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import shutil
from typing import Any, Callable, TypeVar
import uuid

try:
    from tools.bonpreu_auth_probe import (
        ApiError,
        InvalidCredentialsError,
        InvalidEmailCodeError,
        LoginError,
        LoginFlowRunner,
        OAuthUris,
        ProbeError,
        REDIRECT_URI,
        TRANSACTION_TTL_SECONDS,
        TransactionMeta,
        TracePrinter,
        append_query_parameter,
        clean_expired_transactions,
        complete_callback_and_verify,
        delete_transaction,
        ensure_private_dir,
        load_credentials_file,
        load_transaction,
        make_cookie_jar,
        pending_form_from_meta,
        probe_home_dir,
        read_json,
        save_transaction,
        write_private_json,
        MobileApiClient,
    )
except ModuleNotFoundError:
    from bonpreu_auth_probe import (  # type: ignore[no-redef]
        ApiError,
        InvalidCredentialsError,
        InvalidEmailCodeError,
        LoginError,
        LoginFlowRunner,
        OAuthUris,
        ProbeError,
        REDIRECT_URI,
        TRANSACTION_TTL_SECONDS,
        TransactionMeta,
        TracePrinter,
        append_query_parameter,
        clean_expired_transactions,
        complete_callback_and_verify,
        delete_transaction,
        ensure_private_dir,
        load_credentials_file,
        load_transaction,
        make_cookie_jar,
        pending_form_from_meta,
        probe_home_dir,
        read_json,
        save_transaction,
        write_private_json,
        MobileApiClient,
    )

_SESSION_SCHEMA_VERSION = 1
_SESSION_FILE_NAME = "session.json"

T = TypeVar("T")


@dataclass(slots=True)
class LocalSession:
    """Persisted authenticated local session state."""

    schema_version: int
    device_id: str
    device_token: str
    access_token: str
    refresh_token: str | None
    language: str
    created_at: str
    updated_at: str
    last_verified_at: str | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def session_file_path(home: Path) -> Path:
    """Return persisted session path."""
    return home / _SESSION_FILE_NAME


def load_local_session(home: Path) -> LocalSession | None:
    """Load local session from disk if present."""
    path = session_file_path(home)
    if not path.exists():
        return None

    raw = read_json(path)
    schema_version = int(raw.get("schema_version") or 0)
    if schema_version != _SESSION_SCHEMA_VERSION:
        raise ProbeError(
            f"Unsupported local session schema {schema_version} in {path}. "
            "Delete session.json and log in again."
        )

    device_id = str(raw.get("device_id") or "").strip()
    device_token = str(raw.get("device_token") or "").strip()
    access_token = str(raw.get("access_token") or "").strip()
    refresh_token = str(raw.get("refresh_token") or "").strip() or None
    language = str(raw.get("language") or "").strip() or "ca-ES"
    created_at = str(raw.get("created_at") or "").strip()
    updated_at = str(raw.get("updated_at") or "").strip()
    last_verified_at = str(raw.get("last_verified_at") or "").strip() or None

    if not device_id or not device_token or not access_token or not created_at or not updated_at:
        raise ProbeError(f"Session file {path} is missing required fields.")

    return LocalSession(
        schema_version=schema_version,
        device_id=device_id,
        device_token=device_token,
        access_token=access_token,
        refresh_token=refresh_token,
        language=language,
        created_at=created_at,
        updated_at=updated_at,
        last_verified_at=last_verified_at,
    )


def save_local_session(home: Path, session: LocalSession) -> None:
    """Persist local session atomically with restricted permissions."""
    ensure_private_dir(home)
    path = session_file_path(home)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    write_private_json(
        temp_path,
        {
            "schema_version": session.schema_version,
            "device_id": session.device_id,
            "device_token": session.device_token,
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "language": session.language,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "last_verified_at": session.last_verified_at,
        },
    )
    temp_path.replace(path)


def delete_local_session(home: Path) -> None:
    """Delete local session file if present."""
    session_file_path(home).unlink(missing_ok=True)


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))


def _build_session(
    *,
    previous: LocalSession | None,
    device_id: str,
    device_token: str,
    access_token: str,
    refresh_token: str | None,
    language: str,
    last_verified_at: str | None,
) -> LocalSession:
    now = _utc_now_iso()
    return LocalSession(
        schema_version=_SESSION_SCHEMA_VERSION,
        device_id=device_id,
        device_token=device_token,
        access_token=access_token,
        refresh_token=refresh_token or (previous.refresh_token if previous else None),
        language=language,
        created_at=previous.created_at if previous else now,
        updated_at=now,
        last_verified_at=last_verified_at if last_verified_at is not None else (previous.last_verified_at if previous else None),
    )


def _verify_profile_with_refresh(
    *,
    api: MobileApiClient,
    session: LocalSession,
) -> tuple[dict[str, Any], LocalSession]:
    try:
        profile = api.get_user_current(session.access_token)
    except ApiError as err:
        if err.status_code != 401 or not session.refresh_token:
            raise
        refreshed = api.refresh_access_token(
            device_token=session.device_token,
            refresh_token=session.refresh_token,
        )
        session = _build_session(
            previous=session,
            device_id=session.device_id,
            device_token=session.device_token,
            access_token=refreshed.access_token,
            refresh_token=refreshed.refresh_token,
            language=session.language,
            last_verified_at=session.last_verified_at,
        )
        profile = api.get_user_current(session.access_token)

    session = _build_session(
        previous=session,
        device_id=session.device_id,
        device_token=session.device_token,
        access_token=session.access_token,
        refresh_token=session.refresh_token,
        language=session.language,
        last_verified_at=_utc_now_iso(),
    )
    return profile, session


def _request_with_session_refresh(
    *,
    api: MobileApiClient,
    session: LocalSession,
    request_fn: Callable[[str], T],
) -> tuple[T, LocalSession]:
    try:
        response = request_fn(session.access_token)
    except ApiError as err:
        if err.status_code != 401 or not session.refresh_token:
            raise
        refreshed = api.refresh_access_token(
            device_token=session.device_token,
            refresh_token=session.refresh_token,
        )
        session = _build_session(
            previous=session,
            device_id=session.device_id,
            device_token=session.device_token,
            access_token=refreshed.access_token,
            refresh_token=refreshed.refresh_token,
            language=session.language,
            last_verified_at=session.last_verified_at,
        )
        response = request_fn(session.access_token)

    session = _build_session(
        previous=session,
        device_id=session.device_id,
        device_token=session.device_token,
        access_token=session.access_token,
        refresh_token=session.refresh_token,
        language=session.language,
        last_verified_at=session.last_verified_at,
    )
    return response, session


def _extract_products_from_search_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    groups = payload.get("productGroups")
    if not isinstance(groups, list):
        return products

    for group in groups:
        if not isinstance(group, dict):
            continue
        values = group.get("products")
        if not isinstance(values, list):
            values = group.get("decoratedProducts")
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, dict):
                products.append(item)
    return products


def _extract_price_amount(price_payload: dict[str, Any] | None, *paths: tuple[str, ...]) -> str | None:
    if not isinstance(price_payload, dict):
        return None

    def _coerce_value(node: Any) -> str | None:
        if node is None:
            return None
        if isinstance(node, dict):
            if "amount" in node:
                return _coerce_value(node.get("amount"))
            if "format" in node:
                return _coerce_value(node.get("format"))
            return None
        value = str(node).strip()
        return value or None

    for path in paths:
        node: Any = price_payload
        for key in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        value = _coerce_value(node)
        if value:
            return value
    return None


def _normalize_product(product: dict[str, Any]) -> dict[str, Any]:
    payload = product.get("product") if isinstance(product.get("product"), dict) else product
    if not isinstance(payload, dict):
        payload = product

    price_payload = payload.get("price") if isinstance(payload.get("price"), dict) else None
    promotions = payload.get("promotions")
    promotion_count = len(promotions) if isinstance(promotions, list) else (1 if isinstance(payload.get("promotion"), dict) else 0)

    category_path = payload.get("categoryPath")
    categories: list[str] = []
    if isinstance(category_path, list):
        for category in category_path:
            if isinstance(category, dict):
                name = str(category.get("name") or "").strip()
                if name:
                    categories.append(name)

    return {
        "product_id": str(payload.get("productId") or product.get("productId") or "").strip() or None,
        "retailer_product_id": str(payload.get("retailerProductId") or product.get("retailerProductId") or "").strip() or None,
        "name": str(payload.get("description") or payload.get("name") or "").strip() or None,
        "brand": str(payload.get("brand") or "").strip() or None,
        "size": str(payload.get("size") or "").strip() or None,
        "available": payload.get("available") if isinstance(payload.get("available"), bool) else None,
        "max_available_quantity": payload.get("maxAvailableQuantity"),
        "price": _extract_price_amount(price_payload, ("raw", "amount"), ("each", "amount"), ("amount",)),
        "unit_price": _extract_price_amount(
            price_payload,
            ("unit", "amount"),
            ("originalUnit", "amount"),
            ("per", "amount"),
        ),
        "unit": _extract_price_amount(
            price_payload,
            ("unit", "format"),
            ("originalUnit", "format"),
            ("per", "format"),
        ),
        "promotion_count": promotion_count,
        "categories": categories,
    }


def _print_search_human(payload: dict[str, Any]) -> None:
    products = _extract_products_from_search_payload(payload)
    total_products = payload.get("totalProducts")
    next_page_token = payload.get("nextPageToken")

    print(f"SEARCH_RESULT products={len(products)} total={total_products if total_products is not None else 'unknown'}")
    if next_page_token:
        print("SEARCH_RESULT next_page_token=yes")
    else:
        print("SEARCH_RESULT next_page_token=no")

    for index, product in enumerate(products[:20], start=1):
        normalized = _normalize_product(product)
        identifier = normalized.get("retailer_product_id") or normalized.get("product_id") or "unknown"
        name = normalized.get("name") or "(no-name)"
        brand = normalized.get("brand") or ""
        price = normalized.get("price") or "?"
        unit_price = normalized.get("unit_price")
        unit = normalized.get("unit")
        availability = normalized.get("available")
        availability_label = "available" if availability is True else "unavailable" if availability is False else "unknown"
        unit_label = f" {unit_price}/{unit}" if unit_price and unit else ""
        brand_label = f" [{brand}]" if brand else ""
        print(f"{index:02d}. {identifier} {name}{brand_label} price={price}{unit_label} availability={availability_label}")


def _print_product_human(payload: dict[str, Any]) -> None:
    product = payload.get("product")
    if not isinstance(product, dict):
        raise ProbeError("Product detail payload did not include product object.")

    normalized = _normalize_product(product)
    print("PRODUCT_DETAIL")
    for key in (
        "retailer_product_id",
        "product_id",
        "name",
        "brand",
        "size",
        "available",
        "price",
        "unit_price",
        "unit",
        "promotion_count",
    ):
        print(f"- {key}: {normalized.get(key)}")

    fields = payload.get("fields")
    tables = payload.get("tables")
    promotions = payload.get("promotions")
    detailed_images = payload.get("detailedImages")
    print(f"- fields_count: {len(fields) if isinstance(fields, list) else 0}")
    print(f"- tables_count: {len(tables) if isinstance(tables, list) else 0}")
    print(f"- detail_promotions_count: {len(promotions) if isinstance(promotions, list) else 0}")
    print(f"- detailed_images_count: {len(detailed_images) if isinstance(detailed_images, list) else 0}")


def _resolve_oauth_uris(
    *,
    api: MobileApiClient,
    device_token: str,
    use_alternative_mobile: bool,
) -> OAuthUris:
    return api.get_oauth_uris_with_device_token(
        device_token,
        use_alternative_mobile=use_alternative_mobile,
    )


def command_auth_login(args: argparse.Namespace) -> int:
    """Start auth flow and persist local session or pending OTP transaction."""
    home = probe_home_dir()
    clean_expired_transactions(home)

    previous_session = load_local_session(home)
    language = args.language or (previous_session.language if previous_session else "ca-ES")
    credentials = load_credentials_file(home, override=args.credentials_file)

    trace = TracePrinter(verbose=not bool(args.quiet))
    api = MobileApiClient(language=language)
    device_id = previous_session.device_id if previous_session else str(uuid.uuid4())

    trace.info("Starting mobile API device bootstrap.")
    device_token = api.ensure_device_token(device_id)
    trace.info("Device token resolved (value hidden).")
    uris = _resolve_oauth_uris(
        api=api,
        device_token=device_token,
        use_alternative_mobile=bool(args.alternative_mobile),
    )
    authorization_url = append_query_parameter(uris.authentication_uri, "redirect_uri", REDIRECT_URI)
    trace.info("Authorization URI obtained.")

    cookie_jar = make_cookie_jar()
    runner = LoginFlowRunner(cookie_jar=cookie_jar, trace=trace, language=language)
    result = runner.run_start(
        authorization_url=authorization_url,
        username=credentials.username,
        password=credentials.password,
    )

    if result.pending_code_form is not None:
        transaction_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
        meta = TransactionMeta(
            transaction_id=transaction_id,
            created_at=datetime.now(timezone.utc).timestamp(),
            expires_at=datetime.now(timezone.utc).timestamp() + TRANSACTION_TTL_SECONDS,
            oauth_state=uris.state,
            redirect_uri=REDIRECT_URI,
            device_id=device_id,
            device_token=device_token,
            pending_form={
                "method": result.pending_code_form.form.method,
                "action_url": result.pending_code_form.form.action_url,
                "payload_fields": result.pending_code_form.form.payload_fields,
                "controls": [
                    {
                        "name": control.name,
                        "control_type": control.control_type,
                        "value": control.value,
                        "field_id": control.field_id,
                        "autocomplete": control.autocomplete,
                        "maxlength": control.maxlength,
                        "placeholder": control.placeholder,
                    }
                    for control in result.pending_code_form.form.controls
                ],
                "code_field": result.pending_code_form.code_field,
            },
            observed_redirect_uris=list(result.observed_redirect_uris),
        )
        tx_path = save_transaction(home, meta, cookie_jar, trace)
        print(
            f"NEEDS_EMAIL_CODE transaction_id={transaction_id} expires_in={TRANSACTION_TTL_SECONDS}s "
            f"state_dir={tx_path}"
        )
        return 20

    if not result.callback_url:
        raise LoginError("Login ended without callback URL.")

    pair, _ = complete_callback_and_verify(
        callback_url=result.callback_url,
        expected_state=uris.state,
        redirect_uri=REDIRECT_URI,
        device_token=device_token,
        observed_redirect_uris=result.observed_redirect_uris,
        api=api,
    )
    new_session = _build_session(
        previous=previous_session,
        device_id=device_id,
        device_token=device_token,
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        language=language,
        last_verified_at=_utc_now_iso(),
    )
    save_local_session(home, new_session)
    print("RESULT session_saved=yes")
    print("RESULT callback_captured=yes")
    print("RESULT state_valid=yes")
    print("RESULT access_token=yes")
    print("RESULT profile_verified=yes")
    return 0


def command_auth_resume(args: argparse.Namespace) -> int:
    """Resume pending OTP transaction and persist local session."""
    home = probe_home_dir()
    clean_expired_transactions(home)
    previous_session = load_local_session(home)
    language = args.language or (previous_session.language if previous_session else "ca-ES")

    transaction_id = str(args.transaction_id or "").strip()
    if not transaction_id:
        raise ProbeError("--transaction-id is required")

    otp = str(args.otp or "").strip()
    if args.otp_stdin:
        import sys

        otp = (sys.stdin.readline() or "").strip()
    if not otp:
        raise ProbeError("OTP code is required. Use --otp or --otp-stdin.")

    meta, cookie_jar, previous_trace = load_transaction(home, transaction_id)
    trace = TracePrinter(verbose=not bool(args.quiet))
    if previous_trace:
        trace.info("Resuming transaction with existing trace context.")
        for line in previous_trace:
            trace.info(f"PREV {line}")

    pending_form = pending_form_from_meta(meta.pending_form)
    runner = LoginFlowRunner(cookie_jar=cookie_jar, trace=trace, language=language)
    result = runner.run_resume(pending=pending_form, email_code=otp)
    if result.pending_code_form is not None:
        meta.pending_form = {
            "method": result.pending_code_form.form.method,
            "action_url": result.pending_code_form.form.action_url,
            "payload_fields": result.pending_code_form.form.payload_fields,
            "controls": [
                {
                    "name": control.name,
                    "control_type": control.control_type,
                    "value": control.value,
                    "field_id": control.field_id,
                    "autocomplete": control.autocomplete,
                    "maxlength": control.maxlength,
                    "placeholder": control.placeholder,
                }
                for control in result.pending_code_form.form.controls
            ],
            "code_field": result.pending_code_form.code_field,
        }
        save_transaction(home, meta, cookie_jar, trace)
        raise InvalidEmailCodeError("Email code rejected; transaction updated for retry.")

    if not result.callback_url:
        raise LoginError("Resume phase ended without callback URL.")

    api = MobileApiClient(language=language)
    pair, _ = complete_callback_and_verify(
        callback_url=result.callback_url,
        expected_state=meta.oauth_state,
        redirect_uri=meta.redirect_uri,
        device_token=meta.device_token,
        observed_redirect_uris=meta.observed_redirect_uris,
        api=api,
    )

    session = _build_session(
        previous=previous_session,
        device_id=meta.device_id,
        device_token=meta.device_token,
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        language=language,
        last_verified_at=_utc_now_iso(),
    )
    save_local_session(home, session)
    delete_transaction(home, transaction_id)
    print("RESULT session_saved=yes")
    print("RESULT callback_captured=yes")
    print("RESULT state_valid=yes")
    print("RESULT access_token=yes")
    print("RESULT profile_verified=yes")
    return 0


def command_auth_status(args: argparse.Namespace) -> int:
    """Show local session status without exposing secrets."""
    home = probe_home_dir()
    session = load_local_session(home)
    if session is None:
        if args.json_output:
            _print_json(
                {
                    "authenticated": False,
                    "session_file": str(session_file_path(home)),
                }
            )
        else:
            print("STATUS authenticated=no")
            print(f"STATUS session_file={session_file_path(home)}")
        return 0

    if args.json_output:
        _print_json(
            {
                "authenticated": True,
                "session_file": str(session_file_path(home)),
                "schema_version": session.schema_version,
                "has_refresh_token": bool(session.refresh_token),
                "language": session.language,
                "created_at": session.created_at,
                "updated_at": session.updated_at,
                "last_verified_at": session.last_verified_at,
                "device_id_profile": {
                    "length": len(session.device_id),
                },
            }
        )
    else:
        print("STATUS authenticated=yes")
        print(f"STATUS session_file={session_file_path(home)}")
        print(f"STATUS has_refresh_token={'yes' if session.refresh_token else 'no'}")
        print(f"STATUS language={session.language}")
        print(f"STATUS created_at={session.created_at}")
        print(f"STATUS updated_at={session.updated_at}")
        print(f"STATUS last_verified_at={session.last_verified_at or 'never'}")
    return 0


def command_auth_verify(args: argparse.Namespace) -> int:
    """Verify local session via v1/user/current, refreshing token if needed."""
    home = probe_home_dir()
    session = load_local_session(home)
    if session is None:
        raise ProbeError("No local session found. Run `auth login` first.")

    language = args.language or session.language
    api = MobileApiClient(language=language)
    profile, updated = _verify_profile_with_refresh(api=api, session=session)
    save_local_session(home, updated)
    if args.json_output:
        _print_json(
            {
                "verified": True,
                "profile_keys": sorted(profile.keys()),
                "retailer_customer_id": str(
                    profile.get("retailerCustomerId")
                    or profile.get("customerId")
                    or profile.get("id")
                    or ""
                ).strip()
                or None,
            }
        )
    else:
        print("RESULT verified=yes")
        print(f"RESULT profile_keys={sorted(profile.keys())}")
    return 0


def command_auth_logout(args: argparse.Namespace) -> int:
    """Delete local session but keep credentials and transactions."""
    del args
    home = probe_home_dir()
    delete_local_session(home)
    print("RESULT session_deleted=yes")
    return 0


def command_auth_reset_device(args: argparse.Namespace) -> int:
    """Delete local session and pending OTP transactions."""
    del args
    home = probe_home_dir()
    delete_local_session(home)
    transactions_dir = home / "transactions"
    if transactions_dir.exists():
        shutil.rmtree(transactions_dir, ignore_errors=True)
    print("RESULT session_deleted=yes")
    print("RESULT transactions_deleted=yes")
    return 0


def command_catalog_search(args: argparse.Namespace) -> int:
    """Search products with the authenticated mobile API session."""
    home = probe_home_dir()
    session = load_local_session(home)
    if session is None:
        raise ProbeError("No local session found. Run `auth login` first.")

    language = args.language or session.language
    api = MobileApiClient(language=language)

    response, updated = _request_with_session_refresh(
        api=api,
        session=session,
        request_fn=lambda access_token: api.search_products(
            access_token=access_token,
            query=args.query,
            screen_size=args.screen_size,
            max_products_to_decorate=args.max_products_to_decorate,
            max_page_size=args.max_page_size,
            include_additional_page_info=not bool(args.no_additional_page_info),
            sort_option_id=args.sort_option_id,
            encoded_filters=args.encoded_filters,
            category_id=args.category_id,
            page_token=args.page_token,
        ),
    )
    save_local_session(home, updated)
    if args.json_output:
        _print_json(response)
    else:
        _print_search_human(response)
    return 0


def command_catalog_product(args: argparse.Namespace) -> int:
    """Fetch product detail by retailer product ID."""
    home = probe_home_dir()
    session = load_local_session(home)
    if session is None:
        raise ProbeError("No local session found. Run `auth login` first.")

    language = args.language or session.language
    api = MobileApiClient(language=language)
    response, updated = _request_with_session_refresh(
        api=api,
        session=session,
        request_fn=lambda access_token: api.get_product_detail(
            access_token=access_token,
            retailer_product_id=args.retailer_product_id,
        ),
    )
    save_local_session(home, updated)
    if args.json_output:
        _print_json(response)
    else:
        _print_product_human(response)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for local catalog probe."""
    parser = argparse.ArgumentParser(description="Bonpreu local catalog probe")
    subparsers = parser.add_subparsers(dest="domain", required=True)

    auth = subparsers.add_parser("auth", help="authentication and local session commands")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)

    login = auth_sub.add_parser("login", help="run credential login flow")
    login.add_argument("--language", default="", help="Accept-Language header (default: session or ca-ES)")
    login.add_argument(
        "--credentials-file",
        default="",
        help="credentials JSON path (default: ~/.bonpreu-auth-probe/credentials.json)",
    )
    login.add_argument(
        "--alternative-mobile",
        action="store_true",
        help="use v1/authorize/uris/alternative-mobile",
    )
    login.add_argument("--quiet", action="store_true", help="suppress verbose trace output")
    login.set_defaults(func=command_auth_login)

    resume = auth_sub.add_parser("resume", help="resume pending OTP transaction")
    resume.add_argument("--transaction-id", required=True, help="pending transaction identifier")
    resume.add_argument("--otp", default="", help="email verification code")
    resume.add_argument("--otp-stdin", action="store_true", help="read OTP code from stdin")
    resume.add_argument("--language", default="", help="Accept-Language header (default: session or ca-ES)")
    resume.add_argument("--quiet", action="store_true", help="suppress verbose trace output")
    resume.set_defaults(func=command_auth_resume)

    status = auth_sub.add_parser("status", help="show local session status")
    status.add_argument("--json", dest="json_output", action="store_true", help="output JSON")
    status.set_defaults(func=command_auth_status)

    verify = auth_sub.add_parser("verify", help="verify local session and refresh if needed")
    verify.add_argument("--language", default="", help="Accept-Language header override")
    verify.add_argument("--json", dest="json_output", action="store_true", help="output JSON")
    verify.set_defaults(func=command_auth_verify)

    logout = auth_sub.add_parser("logout", help="delete local session")
    logout.set_defaults(func=command_auth_logout)

    reset = auth_sub.add_parser("reset-device", help="delete local session and pending transactions")
    reset.set_defaults(func=command_auth_reset_device)

    catalog = subparsers.add_parser("catalog", help="catalog commands")
    catalog_sub = catalog.add_subparsers(dest="catalog_command", required=True)

    search = catalog_sub.add_parser("search", help="search products")
    search.add_argument("query", help="search text")
    search.add_argument("--language", default="", help="Accept-Language header override")
    search.add_argument("--screen-size", default="S", choices=["S", "M", "L", "XL", "UNKNOWN"])
    search.add_argument("--max-products-to-decorate", type=int, default=100)
    search.add_argument("--max-page-size", type=int, default=30)
    search.add_argument("--sort-option-id", default="")
    search.add_argument("--encoded-filters", default="", help="already URL-encoded filters expression")
    search.add_argument("--category-id", default="")
    search.add_argument("--page-token", default="")
    search.add_argument("--no-additional-page-info", action="store_true")
    search.add_argument("--json", dest="json_output", action="store_true", help="output raw JSON payload")
    search.set_defaults(func=command_catalog_search)

    product = catalog_sub.add_parser("product", help="fetch product detail by retailer product ID")
    product.add_argument("retailer_product_id", help="retailer product identifier")
    product.add_argument("--language", default="", help="Accept-Language header override")
    product.add_argument("--json", dest="json_output", action="store_true", help="output raw JSON payload")
    product.set_defaults(func=command_catalog_product)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Program entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.func(args))
    except InvalidCredentialsError as err:
        print(f"ERROR invalid_credentials: {err}")
        return 11
    except InvalidEmailCodeError as err:
        print(f"ERROR invalid_email_code: {err}")
        return 12
    except LoginError as err:
        print(f"ERROR login: {err}")
        return 13
    except ApiError as err:
        print(f"ERROR api: {err}")
        return 14
    except ProbeError as err:
        print(f"ERROR probe: {err}")
        return 1
    except KeyboardInterrupt:
        print("ERROR interrupted")
        return 130
    except Exception as err:  # pragma: no cover - defensive fallback
        print(f"ERROR unexpected: {err.__class__.__name__}")
        return 99


if __name__ == "__main__":
    raise SystemExit(main())
