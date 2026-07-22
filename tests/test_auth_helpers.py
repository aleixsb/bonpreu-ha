"""Tests for OAuth callback auth helpers."""

from __future__ import annotations

import base64
import sys
import types
import unittest


def _install_homeassistant_stubs() -> None:
    if "homeassistant" in sys.modules:
        return

    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []
    config_entries = types.ModuleType("homeassistant.config_entries")
    const = types.ModuleType("homeassistant.const")
    core = types.ModuleType("homeassistant.core")
    aiohttp_client = types.ModuleType("homeassistant.helpers.aiohttp_client")

    class ConfigEntry:
        pass

    class Platform:
        SENSOR = "sensor"
        TODO = "todo"

    class HomeAssistant:
        pass

    config_entries.ConfigEntry = ConfigEntry
    const.CONF_LANGUAGE = "language"
    const.Platform = Platform
    core.HomeAssistant = HomeAssistant
    aiohttp_client.async_get_clientsession = lambda hass: None

    sys.modules["homeassistant"] = homeassistant
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.const"] = const
    sys.modules["homeassistant.core"] = core
    sys.modules["homeassistant.helpers"] = types.ModuleType("homeassistant.helpers")
    sys.modules["homeassistant.helpers.aiohttp_client"] = aiohttp_client


_install_homeassistant_stubs()

from custom_components.bonpreu.api.auth import (
    callback_redirect_uri_candidate,
    expand_redirect_candidate_variants,
    infer_redirect_candidates_from_state,
    is_expected_callback_url,
    is_intermediate_callback_url,
    parse_callback_query,
    parse_query_preserving_plus,
    parse_query_raw,
    parse_callback_url,
    states_match,
)


class AuthHelpersTests(unittest.TestCase):
    def test_parse_intermediate_callback_query(self) -> None:
        url = (
            "https://www.compraonline.bonpreuesclat.cat/sso-login?"
            "state=abc123&code=auth-code"
        )
        parsed = parse_callback_query(url)
        self.assertEqual(parsed.state, "abc123")
        self.assertEqual(parsed.code, "auth-code")
        self.assertEqual(parsed.raw_code, "auth-code")

    def test_parse_callback_query_preserves_plus(self) -> None:
        parsed = parse_callback_query("bonpreu-atm://login?state=s1&code=a+b")
        self.assertEqual(parsed.code, "a+b")
        self.assertEqual(parsed.raw_code, "a+b")

    def test_parse_query_raw_keeps_percent_encoding(self) -> None:
        decoded = parse_query_preserving_plus("code=a%2Bb")
        raw = parse_query_raw("code=a%2Bb")
        self.assertEqual(decoded["code"], ["a+b"])
        self.assertEqual(raw["code"], ["a%2Bb"])

    def test_parse_expected_mobile_callback(self) -> None:
        callback = "bonpreu-atm://login?state=foo&code=bar"
        parsed = parse_callback_url(callback)
        self.assertEqual(parsed.state, "foo")
        self.assertEqual(parsed.code, "bar")

    def test_state_match_for_wrapped_mobile_state_with_raw_uuid_suffix(self) -> None:
        expected_state = "e385e116-018d-45f1-81f8-ddb84df403c1"
        received_state = (
            "mobile_Ym9ucHJldS1hdG06Ly9sb2dpbg==_"
            "ZTM4NWUxMTYtMDE4ZC00NWYxLTgxZjgtZGRiODRkZjQwM2Mx_"
            "68b543b2-04d6-4e9c-9a33-90dcdfa4bd3f"
        )
        self.assertTrue(
            states_match(
                expected_state,
                received_state,
                expected_redirect_uri="bonpreu-atm://login",
            )
        )

    def test_state_match_supports_urlsafe_base64_without_padding(self) -> None:
        expected_redirect = "https://ha.example.com/api/bonpreu/oauth/nonce_with_chars"
        expected_state = "state_value_with_underscores"
        encoded_redirect = base64.urlsafe_b64encode(expected_redirect.encode()).decode().rstrip("=")
        encoded_state = base64.urlsafe_b64encode(expected_state.encode()).decode().rstrip("=")
        received_state = (
            f"mobile_{encoded_redirect}_{encoded_state}_"
            "68b543b2-04d6-4e9c-9a33-90dcdfa4bd3f"
        )

        self.assertTrue(
            states_match(
                expected_state,
                received_state,
                expected_redirect_uri=expected_redirect,
            )
        )

    def test_expected_callback_url_rejects_wrong_scheme(self) -> None:
        self.assertFalse(
            is_expected_callback_url(
                "https://login?state=s&code=c",
                expected_redirect_uri="bonpreu-atm://login",
            )
        )

    def test_intermediate_callback_url_matcher(self) -> None:
        self.assertTrue(
            is_intermediate_callback_url(
                "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s&code=c"
            )
        )

    def test_infer_redirect_candidates_from_wrapped_state(self) -> None:
        redirect = "https://www.compraonline.bonpreuesclat.cat/sso-login/auth"
        expected_state = "state-123"
        encoded_redirect = base64.b64encode(redirect.encode()).decode().rstrip("=")
        encoded_state = base64.b64encode(expected_state.encode()).decode().rstrip("=")
        received_state = f"mobile_{encoded_redirect}_{encoded_state}_68b543b2-04d6-4e9c-9a33-90dcdfa4bd3f"

        candidates = infer_redirect_candidates_from_state(
            expected_state=expected_state,
            received_state=received_state,
            default_redirect_uri="bonpreu-atm://login",
        )
        self.assertEqual(candidates[0], "bonpreu-atm://login")
        self.assertIn(redirect, candidates)

    def test_expand_redirect_candidates_adds_intermediate_pair(self) -> None:
        expanded = expand_redirect_candidate_variants(
            ["https://www.compraonline.bonpreuesclat.cat/sso-login"]
        )
        self.assertIn("https://www.compraonline.bonpreuesclat.cat/sso-login/auth", expanded)

    def test_callback_redirect_uri_candidate_for_intermediate(self) -> None:
        candidate = callback_redirect_uri_candidate(
            "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1"
        )
        self.assertEqual(candidate, "https://www.compraonline.bonpreuesclat.cat/sso-login")


if __name__ == "__main__":
    unittest.main()
