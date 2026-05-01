from __future__ import annotations

import sys
import types

from gcpwn.modules.opengraph.enumeration.enum_gcp_cloud_hound_data import push_custom_node_attributes


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_key_custom_nodes_push_falls_back_to_post_on_405(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def _request(method, url, **kwargs):
        _ = kwargs
        calls.append((str(method), str(url)))
        if method == "PUT":
            return _FakeResponse(405, "method not allowed")
        if method == "POST":
            return _FakeResponse(200, "ok")
        return _FakeResponse(500, "unexpected")

    fake_requests = types.SimpleNamespace(request=_request)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    result = push_custom_node_attributes(
        custom_nodes_url="http://127.0.0.1:8080",
        custom_nodes_token="test-token",
    )

    assert result["ok"] is True
    assert result["method"] == "POST"
    assert result["url"] == "http://127.0.0.1:8080/api/v2/custom-nodes"
    assert calls[:2] == [
        ("PUT", "http://127.0.0.1:8080/api/v2/custom-nodes"),
        ("POST", "http://127.0.0.1:8080/api/v2/custom-nodes"),
    ]


def test_key_custom_nodes_push_tries_alternate_path_when_default_path_fails(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def _request(method, url, **kwargs):
        _ = kwargs
        calls.append((str(method), str(url)))
        if url.endswith("/api/v2/custom-nodes"):
            return _FakeResponse(404, "not found")
        if url.endswith("/api/v2/custom-node-types") and method == "POST":
            return _FakeResponse(200, "ok")
        return _FakeResponse(405, "method not allowed")

    fake_requests = types.SimpleNamespace(request=_request)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    result = push_custom_node_attributes(
        custom_nodes_url="http://127.0.0.1:8080",
        custom_nodes_token="test-token",
    )

    assert result["ok"] is True
    assert result["method"] == "POST"
    assert result["url"] == "http://127.0.0.1:8080/api/v2/custom-node-types"
    assert any(url.endswith("/api/v2/custom-nodes") for _method, url in calls)
    assert any(url.endswith("/api/v2/custom-node-types") for _method, url in calls)


def test_key_custom_nodes_push_skips_without_token() -> None:
    result = push_custom_node_attributes(
        custom_nodes_url="http://127.0.0.1:8080",
        custom_nodes_token="",
    )

    assert result == {"ok": False, "reason": "missing_token"}
