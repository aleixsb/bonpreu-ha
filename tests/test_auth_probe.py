"""Unit tests for standalone auth probe helpers."""

from __future__ import annotations

import base64
import unittest

from tools.bonpreu_auth_probe import (
    callback_redirect_uri_candidate,
    ChallengeRequiredError,
    classify_login_retry_reason,
    collect_redirect_uri_candidates,
    decode_base64_text_variants,
    EmailCodeFormSelection,
    expand_redirect_candidate_variants,
    FormControl,
    ParsedForm,
    extract_callback_url,
    extract_callback_url_from_location,
    extract_mobile_callback_url,
    extract_mobile_callback_url_from_location,
    extract_mobile_callback_url_from_html,
    extract_html_hints,
    maybe_raise_challenge,
    normalize_api_language,
    parse_forms,
    parse_query_preserving_plus,
    parse_query_raw,
    pending_form_from_meta,
    promote_intermediate_callback_url,
    sanitize_url_for_log,
    select_credentials_form,
    select_email_code_form,
    infer_redirect_candidates_from_state,
    is_intermediate_callback_url,
    states_match,
)


class AuthProbeHelperTests(unittest.TestCase):
    def test_normalize_language(self) -> None:
        self.assertEqual(normalize_api_language("ca"), "ca-ES")
        self.assertEqual(normalize_api_language("es_MX"), "es-ES")
        self.assertEqual(normalize_api_language("en"), "ca-ES")

    def test_extract_callback_mobile_and_intermediate(self) -> None:
        self.assertEqual(
            extract_callback_url("bonpreu-atm://login?state=s1&code=c1"),
            "bonpreu-atm://login?state=s1&code=c1",
        )
        self.assertEqual(
            extract_callback_url(
                "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1"
            ),
            "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1",
        )

    def test_extract_callback_location_relative(self) -> None:
        self.assertEqual(
            extract_callback_url_from_location(
                "https://www.compraonline.bonpreuesclat.cat/sso-login/auth",
                "/sso-login?state=s1&code=c1",
            ),
            "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1",
        )

    def test_extract_mobile_callback_only(self) -> None:
        self.assertEqual(
            extract_mobile_callback_url("bonpreu-atm://login?state=s1&code=c1"),
            "bonpreu-atm://login?state=s1&code=c1",
        )
        self.assertIsNone(
            extract_mobile_callback_url(
                "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1"
            )
        )

    def test_is_intermediate_callback_url(self) -> None:
        self.assertTrue(
            is_intermediate_callback_url(
                "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1"
            )
        )
        self.assertFalse(is_intermediate_callback_url("bonpreu-atm://login?state=s1&code=c1"))

    def test_promote_intermediate_callback_url(self) -> None:
        promoted = promote_intermediate_callback_url(
            "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s1&code=c1"
        )
        self.assertEqual(
            promoted,
            "https://www.compraonline.bonpreuesclat.cat/sso-login/auth?state=s1&code=c1",
        )

    def test_extract_mobile_callback_from_location(self) -> None:
        self.assertEqual(
            extract_mobile_callback_url_from_location(
                "https://www.compraonline.bonpreuesclat.cat/sso-login/auth",
                "bonpreu-atm://login?state=s1&code=c1",
            ),
            "bonpreu-atm://login?state=s1&code=c1",
        )

    def test_extract_mobile_callback_from_html(self) -> None:
        html = "<script>window.location='bonpreu-atm://login?state=s1&code=c1'</script>"
        self.assertEqual(
            extract_mobile_callback_url_from_html(html),
            "bonpreu-atm://login?state=s1&code=c1",
        )

    def test_extract_mobile_callback_from_html_escaped(self) -> None:
        html = "<script>window.location='bonpreu-atm:\\/\\/login?state=s1&code=c1'</script>"
        self.assertEqual(
            extract_mobile_callback_url_from_html(html),
            "bonpreu-atm://login?state=s1&code=c1",
        )

    def test_parse_and_select_forms(self) -> None:
        html = """
        <html><body>
          <form method=\"post\" action=\"/login\">
            <input type=\"hidden\" name=\"_csrf\" value=\"abc\" />
            <input type=\"email\" name=\"username\" autocomplete=\"username\" />
            <input type=\"password\" name=\"password\" autocomplete=\"current-password\" />
            <button type=\"submit\">Sign in</button>
          </form>
          <form method=\"post\" action=\"/verify\">
            <input type=\"hidden\" name=\"_csrf\" value=\"xyz\" />
            <input type=\"number\" name=\"verificationCode\" maxlength=\"6\" />
          </form>
        </body></html>
        """

        forms = parse_forms(html, base_url="https://app.bonpreu.cat/openid-connect-server-webapp/login")
        credentials = select_credentials_form(forms)
        email_code = select_email_code_form(forms)

        self.assertIsNotNone(credentials)
        self.assertIsNotNone(email_code)
        assert credentials is not None
        assert email_code is not None
        self.assertEqual(credentials.username_field, "username")
        self.assertEqual(credentials.password_field, "password")
        self.assertEqual(email_code.code_field, "verificationCode")

    def test_states_match_wrapped_mobile(self) -> None:
        expected_state = "e385e116-018d-45f1-81f8-ddb84df403c1"
        expected_redirect = "bonpreu-atm://login"
        encoded_redirect = base64.b64encode(expected_redirect.encode()).decode()
        encoded_state = base64.b64encode(expected_state.encode()).decode().rstrip("=")
        received = f"mobile_{encoded_redirect}_{encoded_state}_68b543b2-04d6-4e9c-9a33-90dcdfa4bd3f"

        self.assertTrue(states_match(expected_state, received, expected_redirect_uri=expected_redirect))

    def test_pending_form_from_meta_roundtrip(self) -> None:
        raw = {
            "method": "POST",
            "action_url": "https://app.bonpreu.cat/verify",
            "payload_fields": {"_csrf": "abc"},
            "controls": [
                {
                    "name": "verificationCode",
                    "control_type": "number",
                    "value": "",
                    "field_id": "code",
                    "autocomplete": "one-time-code",
                    "maxlength": "6",
                    "placeholder": "",
                }
            ],
            "code_field": "verificationCode",
        }
        selection = pending_form_from_meta(raw)
        self.assertIsInstance(selection, EmailCodeFormSelection)
        self.assertEqual(selection.code_field, "verificationCode")
        self.assertEqual(selection.form.payload_fields.get("_csrf"), "abc")

    def test_infer_redirect_candidates_from_wrapped_state(self) -> None:
        expected_state = "e385e116-018d-45f1-81f8-ddb84df403c1"
        redirect = "bonpreu-atm://login"
        encoded_redirect = base64.b64encode(redirect.encode()).decode().rstrip("=")
        encoded_state = base64.b64encode(expected_state.encode()).decode().rstrip("=")
        received = f"mobile_{encoded_redirect}_{encoded_state}_68b543b2-04d6-4e9c-9a33-90dcdfa4bd3f"

        candidates = infer_redirect_candidates_from_state(
            expected_state=expected_state,
            received_state=received,
            default_redirect_uri=redirect,
        )
        self.assertIn(redirect, candidates)

    def test_decode_base64_text_variants(self) -> None:
        encoded = "Ym9ucHJldS1hdG06Ly9sb2dpbg"
        decoded = decode_base64_text_variants(encoded)
        self.assertIn("bonpreu-atm://login", decoded)

    def test_callback_redirect_uri_candidate(self) -> None:
        candidate = callback_redirect_uri_candidate(
            "https://www.compraonline.bonpreuesclat.cat/sso-login?state=s&code=c"
        )
        self.assertEqual(candidate, "https://www.compraonline.bonpreuesclat.cat/sso-login")

    def test_sanitize_url_for_log(self) -> None:
        self.assertEqual(
            sanitize_url_for_log("https://example.com/path?a=1&b=2#frag"),
            "https://example.com/path",
        )

    def test_expand_redirect_candidate_variants(self) -> None:
        expanded = expand_redirect_candidate_variants(
            [
                "bonpreu-atm://login/",
                "https://www.compraonline.bonpreuesclat.cat/sso-login",
            ]
        )
        self.assertIn("bonpreu-atm://login", expanded)
        self.assertIn("https://www.compraonline.bonpreuesclat.cat/sso-login/auth", expanded)

    def test_parse_query_preserving_plus(self) -> None:
        parsed = parse_query_preserving_plus("code=ab+c%2Bd&state=s1")
        self.assertEqual(parsed["code"][0], "ab+c+d")
        self.assertEqual(parsed["state"][0], "s1")

    def test_parse_query_raw(self) -> None:
        parsed = parse_query_raw("code=ab+c%2Bd&state=s1")
        self.assertEqual(parsed["code"][0], "ab+c%2Bd")
        self.assertEqual(parsed["state"][0], "s1")

    def test_collect_redirect_uri_candidates(self) -> None:
        sink: list[str] = []
        collect_redirect_uri_candidates(
            "https://app.bonpreu.cat/auth?client_id=mobile&redirect_uri=bonpreu-atm%3A%2F%2Flogin",
            sink,
        )
        self.assertIn("bonpreu-atm://login", sink)

    def test_select_email_code_form_single_candidate(self) -> None:
        form = ParsedForm(
            method="POST",
            action_url="https://app.bonpreu.cat/verify",
            controls=[
                FormControl(
                    name="input1",
                    control_type="number",
                    value="",
                    field_id="",
                    autocomplete="",
                    maxlength="6",
                    placeholder="",
                )
            ],
            payload_fields={"input1": ""},
        )
        selected = select_email_code_form([form])
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.code_field, "input1")

    def test_maybe_raise_challenge_allows_recaptcha_login_form(self) -> None:
        html = """
        <form method=\"post\" action=\"/login\">
          <input type=\"text\" name=\"username\" />
          <input type=\"password\" name=\"password\" />
          <input type=\"hidden\" id=\"bp-recaptcha-required\" name=\"bp-recaptcha-required\" value=\"true\" />
        </form>
        """
        forms = parse_forms(html, base_url="https://app.bonpreu.cat/login")
        maybe_raise_challenge(200, html, "https://app.bonpreu.cat/login", forms=forms)

    def test_maybe_raise_challenge_raises_on_block_page(self) -> None:
        with self.assertRaises(ChallengeRequiredError):
            maybe_raise_challenge(
                403,
                "<html><body>Just a moment... cf-challenge</body></html>",
                "https://app.bonpreu.cat/keycloak/auth",
                forms=[],
            )

    def test_classify_login_retry_reason_captcha(self) -> None:
        html = "<html><body><input name='g-recaptcha-response'/>Please verify you are human</body></html>"
        self.assertEqual(classify_login_retry_reason(html), "captcha")

    def test_classify_login_retry_reason_credentials(self) -> None:
        html = "<html><body>Invalid username or password</body></html>"
        self.assertEqual(classify_login_retry_reason(html), "credentials")

    def test_extract_html_hints(self) -> None:
        html = """
        <html><body>
          <div class='msg'>Invalid username or password.</div>
          <div>reCAPTCHA verification failed</div>
          <script>var token='secret';</script>
        </body></html>
        """
        hints = extract_html_hints(html)
        self.assertTrue(any("Invalid username or password." in hint for hint in hints))
        self.assertTrue(any("reCAPTCHA verification failed" in hint for hint in hints))


if __name__ == "__main__":
    unittest.main()
