from __future__ import annotations

import socket
import sys
import types
from importlib import import_module

import pytest


def _install_google_stubs() -> None:
    try:
        import_module("google.cloud")  # pragma: no cover

        return
    except Exception:
        pass

    google_mod = types.ModuleType("google")
    google_mod.__path__ = []

    api_core_mod = types.ModuleType("google.api_core")
    api_core_mod.__path__ = []
    api_core_exceptions_mod = types.ModuleType("google.api_core.exceptions")

    class _Forbidden(Exception):
        pass

    class _NotFound(Exception):
        pass

    api_core_exceptions_mod.Forbidden = _Forbidden
    api_core_exceptions_mod.NotFound = _NotFound

    cloud_mod = types.ModuleType("google.cloud")
    cloud_mod.__path__ = []
    for name in [
        "compute_v1",
        "functions_v2",
        "iam_admin_v1",
        "resourcemanager_v3",
        "run_v2",
        "secretmanager_v1",
        "storage",
        "tasks_v2",
        "bigquery",
    ]:
        module = types.ModuleType(f"google.cloud.{name}")
        setattr(cloud_mod, name, module)
        sys.modules.setdefault(f"google.cloud.{name}", module)

    protobuf_mod = types.ModuleType("google.protobuf")
    protobuf_mod.__path__ = []
    protobuf_json_format_mod = types.ModuleType("google.protobuf.json_format")
    protobuf_json_format_mod.MessageToDict = lambda value, **_kwargs: value

    iam_mod = types.ModuleType("google.iam")
    iam_mod.__path__ = []
    iam_v1_mod = types.ModuleType("google.iam.v1")
    iam_v1_mod.__path__ = []
    iam_policy_pb2_mod = types.ModuleType("google.iam.v1.iam_policy_pb2")

    class _GetIamPolicyRequest:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class _SetIamPolicyRequest:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    iam_policy_pb2_mod.GetIamPolicyRequest = _GetIamPolicyRequest
    iam_policy_pb2_mod.SetIamPolicyRequest = _SetIamPolicyRequest

    google_mod.api_core = api_core_mod
    google_mod.cloud = cloud_mod
    google_mod.protobuf = protobuf_mod
    google_mod.iam = iam_mod

    api_core_mod.exceptions = api_core_exceptions_mod
    protobuf_mod.json_format = protobuf_json_format_mod
    iam_mod.v1 = iam_v1_mod
    iam_v1_mod.iam_policy_pb2 = iam_policy_pb2_mod

    sys.modules.setdefault("google", google_mod)
    sys.modules.setdefault("google.api_core", api_core_mod)
    sys.modules.setdefault("google.api_core.exceptions", api_core_exceptions_mod)
    sys.modules.setdefault("google.cloud", cloud_mod)
    sys.modules.setdefault("google.protobuf", protobuf_mod)
    sys.modules.setdefault("google.protobuf.json_format", protobuf_json_format_mod)
    sys.modules.setdefault("google.iam", iam_mod)
    sys.modules.setdefault("google.iam.v1", iam_v1_mod)
    sys.modules.setdefault("google.iam.v1.iam_policy_pb2", iam_policy_pb2_mod)


_install_google_stubs()


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch: pytest.MonkeyPatch):
    def _deny_connect(*_args, **_kwargs):
        raise AssertionError("External network calls are disabled in unit tests.")

    monkeypatch.setattr(socket, "create_connection", _deny_connect)
