"""Tests for credential-login HTML helpers."""

from __future__ import annotations

import asyncio
import sys
import types
import unittest


def _install_aiohttp_stubs() -> None:
    if "aiohttp" in sys.modules:
        return

    aiohttp = types.ModuleType("aiohttp")

    class ClientTimeout:
        def __init__(self, total=None) -> None:
            self.total = total

    class CookieJar:
        def __init__(self, unsafe: bool = False) -> None:
            self.unsafe = unsafe

    class ClientSession:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        async def close(self) -> None:
            return None

    aiohttp.ClientTimeout = ClientTimeout
    aiohttp.CookieJar = CookieJar
    aiohttp.ClientSession = ClientSession
    sys.modules["aiohttp"] = aiohttp


_install_aiohttp_stubs()

from custom_components.bonpreu.api.login import (  # noqa: E402
    BonpreuCredentialLoginTransaction,
    extract_callback_url,
    extract_callback_url_from_location,
    extract_mobile_callback_url,
    extract_mobile_callback_url_from_location,
    extract_mobile_callback_url_from_html,
    parse_html_forms,
    promote_intermediate_callback_url,
    select_credentials_form,
    select_email_code_form,
)
from custom_components.bonpreu.api.exceptions import BonpreuLoginChallengeError


class _SequenceLoginTransaction(BonpreuCredentialLoginTransaction):
    def __init__(self, responses: list[tuple[int, str, str | None, str]]) -> None:
        self._responses = list(responses)
        self._requests: list[tuple[str, str, dict[str, str] | None]] = []
        self._observed_redirect_uris = []
        self._pending_email_code = None
        self._closed = False
        self._created_at = 0.0

    @property
    def requests(self) -> list[tuple[str, str, dict[str, str] | None]]:
        return list(self._requests)

    def _assert_active(self) -> None:
        return

    async def _send_request(
        self,
        *,
        method: str,
        url: str,
        payload: dict[str, str] | None,
    ) -> tuple[int, str, str | None, str]:
        self._requests.append((method, url, payload))
        if not self._responses:
            raise AssertionError("No fake responses left.")
        return self._responses.pop(0)


class LoginHelperTests(unittest.TestCase):
    def test_select_credentials_form(self) -> None:
        html = """
        <html><body>
          <form method=\"post\" action=\"/openid-connect-server-webapp/login\">
            <input type=\"hidden\" name=\"_csrf\" value=\"abc\" />
            <input type=\"email\" name=\"username\" value=\"\" />
            <input type=\"password\" name=\"password\" value=\"\" />
            <button type=\"submit\">Login</button>
          </form>
        </body></html>
        """
        forms = parse_html_forms(html, base_url="https://app.bonpreu.cat/openid-connect-server-webapp/login")
        selected = select_credentials_form(forms)

        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.username_field, "username")
        self.assertEqual(selected.password_field, "password")
        self.assertEqual(
            selected.form.action_url,
            "https://app.bonpreu.cat/openid-connect-server-webapp/login",
        )

    def test_select_email_code_form(self) -> None:
        html = """
        <html><body>
          <form method=\"post\" action=\"/openid-connect-server-webapp/verify\">
            <input type=\"hidden\" name=\"_csrf\" value=\"abc\" />
            <input type=\"text\" name=\"verificationCode\" value=\"\" />
          </form>
        </body></html>
        """
        forms = parse_html_forms(html, base_url="https://app.bonpreu.cat/openid-connect-server-webapp/verify")
        selected = select_email_code_form(forms)

        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.code_field, "verificationCode")

    def test_select_email_code_form_requires_unambiguous_fallback_field(self) -> None:
        html = """
        <html><body>
          <form method="post" action="/verify">
            <input type="text" name="first" value="" />
            <input type="text" name="second" value="" />
          </form>
        </body></html>
        """
        forms = parse_html_forms(html, base_url="https://app.bonpreu.cat/verify")
        selected = select_email_code_form(forms)
        self.assertIsNone(selected)

    def test_extract_callback_url_from_location_supports_relative_redirect(self) -> None:
        callback = extract_callback_url_from_location(
            "https://www.compraonline.bonpreuesclat.cat/sso-login/auth",
            "/sso-login?state=s1&code=c1",
        )
        self.assertEqual(
            callback,
            "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1",
        )

    def test_extract_callback_url_supports_mobile_uri(self) -> None:
        callback = extract_callback_url("bonpreu-atm://login?state=s1&code=c1")
        self.assertEqual(callback, "bonpreu-atm://login?state=s1&code=c1")

    def test_extract_mobile_callback_only_accepts_mobile_uri(self) -> None:
        self.assertEqual(
            extract_mobile_callback_url("bonpreu-atm://login?state=s1&code=c1"),
            "bonpreu-atm://login?state=s1&code=c1",
        )
        self.assertIsNone(
            extract_mobile_callback_url(
                "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1"
            )
        )

    def test_extract_mobile_callback_from_location(self) -> None:
        callback = extract_mobile_callback_url_from_location(
            "https://www.compraonline.bonpreuesclat.cat/sso-login",
            "bonpreu-atm://login?state=s1&code=c1",
        )
        self.assertEqual(callback, "bonpreu-atm://login?state=s1&code=c1")

    def test_extract_callback_url_requires_state_and_code_or_error(self) -> None:
        self.assertIsNone(extract_callback_url("bonpreu-atm://login?code=c1"))
        self.assertIsNone(extract_callback_url("bonpreu-atm://login?state=s1"))

    def test_promote_intermediate_callback_url(self) -> None:
        promoted = promote_intermediate_callback_url(
            "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1"
        )
        self.assertEqual(
            promoted,
            "https://www.compraonline.bonpreuesclat.cat/sso-login/auth?state=s1&code=c1",
        )

    def test_extract_mobile_callback_url_from_html_script(self) -> None:
        html = '<script>window.location="bonpreu-atm://login?state=s1&code=c1";</script>'
        callback = extract_mobile_callback_url_from_html(html)
        self.assertEqual(callback, "bonpreu-atm://login?state=s1&code=c1")

    def test_challenge_detection_ignores_recaptcha_marker_when_form_is_present(self) -> None:
        html = """
        <html><body>
          <form method="post" action="/auth">
            <input type="text" name="username" value="" />
            <input type="password" name="password" value="" />
            <input type="hidden" name="bp-recaptcha-required" value="false" />
          </form>
        </body></html>
        """
        forms = parse_html_forms(html, base_url="https://app.bonpreu.cat/auth")
        BonpreuCredentialLoginTransaction._raise_for_browser_challenge(
            None,
            200,
            html,
            "https://app.bonpreu.cat/auth",
            forms=forms,
        )

    def test_challenge_detection_raises_on_challenge_page(self) -> None:
        html = "<html><body>Just a moment. Verify you are human.</body></html>"
        with self.assertRaises(BonpreuLoginChallengeError):
            BonpreuCredentialLoginTransaction._raise_for_browser_challenge(
                None,
                403,
                html,
                "https://app.bonpreu.cat/auth",
                forms=[],
            )

    def test_email_code_phase_promotes_sso_login_before_returning_callback(self) -> None:
        responses = [
            (
                302,
                "https://app.bonpreu.cat/keycloak/otp",
                "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1",
                "",
            ),
            (
                200,
                "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1",
                None,
                "<html></html>",
            ),
            (
                302,
                "https://www.compraonline.bonpreuesclat.cat/sso-login/auth?state=s1&code=c1",
                "bonpreu-atm://login?state=s1&code=c1",
                "",
            ),
        ]
        transaction = _SequenceLoginTransaction(responses)

        progress = asyncio.run(
            transaction._run_email_code_phase(
                method="POST",
                url="https://app.bonpreu.cat/keycloak/otp",
                payload={"code": "123456"},
            )
        )

        self.assertEqual(progress.callback_url, "bonpreu-atm://login?state=s1&code=c1")
        self.assertEqual(len(transaction.requests), 3)
        self.assertEqual(
            transaction.requests[2][1],
            "https://www.compraonline.bonpreuesclat.cat/sso-login/auth?state=s1&code=c1",
        )


if __name__ == "__main__":
    unittest.main()
