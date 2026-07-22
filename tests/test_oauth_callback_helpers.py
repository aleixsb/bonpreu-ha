"""Tests for OAuth callback receiver helpers."""

from __future__ import annotations

import asyncio
import sys
import types
import unittest


def _install_homeassistant_stubs() -> None:
    homeassistant = sys.modules.get("homeassistant")
    if homeassistant is None:
        homeassistant = types.ModuleType("homeassistant")
        homeassistant.__path__ = []
        sys.modules["homeassistant"] = homeassistant

    components = sys.modules.get("homeassistant.components")
    if components is None:
        components = types.ModuleType("homeassistant.components")
        components.__path__ = []
        sys.modules["homeassistant.components"] = components

    http_mod = sys.modules.get("homeassistant.components.http")
    if http_mod is None:
        http_mod = types.ModuleType("homeassistant.components.http")
        sys.modules["homeassistant.components.http"] = http_mod

    if not hasattr(http_mod, "HomeAssistantView"):
        class HomeAssistantView:
            requires_auth = False
            url = "/"
            name = "test"

            def register(self, hass, app, router) -> None:
                del app, router
                hass._registered_views.append(self.__class__.__name__)

        http_mod.HomeAssistantView = HomeAssistantView

    core_mod = sys.modules.get("homeassistant.core")
    if core_mod is None:
        core_mod = types.ModuleType("homeassistant.core")
        sys.modules["homeassistant.core"] = core_mod
    if not hasattr(core_mod, "HomeAssistant"):
        class HomeAssistant:
            pass

        core_mod.HomeAssistant = HomeAssistant

    data_entry_mod = sys.modules.get("homeassistant.data_entry_flow")
    if data_entry_mod is None:
        data_entry_mod = types.ModuleType("homeassistant.data_entry_flow")
        sys.modules["homeassistant.data_entry_flow"] = data_entry_mod
    if not hasattr(data_entry_mod, "UnknownFlow"):
        class UnknownFlow(Exception):
            pass

        data_entry_mod.UnknownFlow = UnknownFlow

    helpers_mod = sys.modules.get("homeassistant.helpers")
    if helpers_mod is None:
        helpers_mod = types.ModuleType("homeassistant.helpers")
        helpers_mod.__path__ = []
        sys.modules["homeassistant.helpers"] = helpers_mod

    network_mod = sys.modules.get("homeassistant.helpers.network")
    if network_mod is None:
        network_mod = types.ModuleType("homeassistant.helpers.network")
        sys.modules["homeassistant.helpers.network"] = network_mod

    if not hasattr(network_mod, "NoURLAvailableError"):
        class NoURLAvailableError(Exception):
            pass

        network_mod.NoURLAvailableError = NoURLAvailableError

    if not hasattr(network_mod, "get_url"):
        network_mod.get_url = lambda hass, **kwargs: "https://ha.example"


def _install_aiohttp_stubs() -> None:
    aiohttp = sys.modules.get("aiohttp")
    if aiohttp is None:
        aiohttp = types.ModuleType("aiohttp")
        sys.modules["aiohttp"] = aiohttp

    if not hasattr(aiohttp, "web"):
        class Response:
            def __init__(self, text: str = "", status: int = 200, content_type: str | None = None) -> None:
                self.text = text
                self.status = status
                self.content_type = content_type

        aiohttp.web = types.SimpleNamespace(Response=Response, Request=object)


_install_homeassistant_stubs()
_install_aiohttp_stubs()

from custom_components.bonpreu.oauth_callback import (
    BonpreuOAuthCallbackView,
    _consume_pending_callback,
    async_build_flow_callback_url,
    async_register_oauth_callback_view,
)


class _FakeHTTP:
    def __init__(self, hass) -> None:
        self._hass = hass
        self.registered_count = 0

    def register_view(self, view_cls) -> None:
        self.registered_count += 1
        self._hass._registered_views.append(getattr(view_cls, "__name__", str(view_cls)))


class _FakeFlowManager:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def async_configure(self, flow_id: str, user_input: dict[str, str]) -> None:
        self.calls.append((flow_id, user_input))


class _FakeConfigEntries:
    def __init__(self) -> None:
        self.flow = _FakeFlowManager()


class _FakeHass:
    def __init__(self) -> None:
        self.data: dict = {}
        self._registered_views: list[str] = []
        self.http = _FakeHTTP(self)
        self.config_entries = _FakeConfigEntries()


class _FakeQuery:
    def __init__(self, values: dict[str, list[str] | str]) -> None:
        self._values = values

    def getall(self, key: str, default):
        if key not in self._values:
            return default
        raw = self._values[key]
        if isinstance(raw, list):
            return raw
        return [raw]


class _FakeRequest:
    def __init__(self, hass, query: _FakeQuery, query_string: str) -> None:
        self.app = {"hass": hass}
        self.query = query
        self.query_string = query_string


class OAuthCallbackHelperTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.hass = _FakeHass()

    def test_register_view_once(self) -> None:
        async_register_oauth_callback_view(self.hass)
        async_register_oauth_callback_view(self.hass)
        self.assertEqual(self.hass.http.registered_count, 1)

    def test_build_and_consume_callback_nonce(self) -> None:
        callback_url = async_build_flow_callback_url(self.hass, "flow_1")
        self.assertTrue(callback_url.startswith("https://ha.example/api/bonpreu/oauth/"))
        nonce = callback_url.rsplit("/", 1)[-1]

        pending = _consume_pending_callback(self.hass, nonce)
        self.assertIsNotNone(pending)
        self.assertEqual(pending.flow_id, "flow_1")
        self.assertIsNone(_consume_pending_callback(self.hass, nonce))

    async def test_missing_state_does_not_consume_nonce(self) -> None:
        callback_url = async_build_flow_callback_url(self.hass, "flow_2")
        nonce = callback_url.rsplit("/", 1)[-1]

        view = BonpreuOAuthCallbackView()
        request = _FakeRequest(
            self.hass,
            _FakeQuery({"code": "abc"}),
            "code=abc",
        )
        response = await view.get(request, nonce)
        self.assertEqual(response.status, 400)

        pending = _consume_pending_callback(self.hass, nonce)
        self.assertIsNotNone(pending)

    async def test_successful_callback_resumes_flow(self) -> None:
        callback_url = async_build_flow_callback_url(self.hass, "flow_3")
        nonce = callback_url.rsplit("/", 1)[-1]

        view = BonpreuOAuthCallbackView()
        request = _FakeRequest(
            self.hass,
            _FakeQuery({"state": "s1", "code": "c1"}),
            "state=s1&code=c1",
        )
        response = await view.get(request, nonce)
        self.assertEqual(response.status, 200)

        self.assertEqual(len(self.hass.config_entries.flow.calls), 1)
        flow_id, user_input = self.hass.config_entries.flow.calls[0]
        self.assertEqual(flow_id, "flow_3")
        self.assertIn("callback_url", user_input)
        self.assertIsNone(_consume_pending_callback(self.hass, nonce))


if __name__ == "__main__":
    unittest.main()
