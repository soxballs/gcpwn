from __future__ import annotations

from collections.abc import Callable
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_project_id_from_resource,
    resource_name_from_value,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


MODEL_LIST_PATH = Path(__file__).resolve().parent / "data" / "model_list.txt"


# ---------------------------------------------------------------------------
# Shared model inventory
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_model_sections() -> dict[str, tuple[str, ...]]:
    sections: dict[str, list[str]] = {}
    current_section = ""

    for raw_line in MODEL_LIST_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            sections.setdefault(current_section, [])
            continue
        if current_section:
            sections.setdefault(current_section, []).append(line)

    return {section: tuple(values) for section, values in sections.items()}


def _section_models(section: str) -> tuple[str, ...]:
    return _load_model_sections().get(str(section or "").strip(), ())


def _default_section_model(section: str) -> str:
    models = _section_models(section)
    return models[0] if models else ""


def _prefix_model_name(model_name: str, *, prefix: str) -> str:
    value = str(model_name or "").strip()
    if not value:
        return ""
    for known_prefix in ("publishers/google/models/", "models/"):
        if value.startswith(known_prefix):
            value = value.removeprefix(known_prefix)
            break
    return f"{prefix}{value}"


def _prefixed_models(section: str, *, prefix: str) -> tuple[str, ...]:
    return tuple(
        prefixed
        for prefixed in (_prefix_model_name(model_name, prefix=prefix) for model_name in _section_models(section))
        if prefixed
    )


def get_shared_generative_model_names() -> tuple[str, ...]:
    return _section_models("shared_generative_models")


def get_gemini_model_list() -> tuple[str, ...]:
    return _prefixed_models("shared_generative_models", prefix="models/")


def get_default_gemini_model() -> str:
    return _prefix_model_name(
        _default_section_model("shared_generative_models"),
        prefix="models/",
    )


def get_vertex_model_list() -> tuple[str, ...]:
    return _prefixed_models("shared_generative_models", prefix="publishers/google/models/")


def get_default_vertex_model() -> str:
    return _prefix_model_name(
        _default_section_model("shared_generative_models"),
        prefix="publishers/google/models/",
    )


def get_gemini_embedding_model_list() -> tuple[str, ...]:
    return _prefixed_models("gemini_embedding_models", prefix="models/")


def get_default_gemini_embedding_model() -> str:
    return _prefix_model_name(
        _default_section_model("gemini_embedding_models"),
        prefix="models/",
    )


# ---------------------------------------------------------------------------
# Shared model cycle + prompt helpers
# ---------------------------------------------------------------------------


def build_model_cycle(
    primary_model: str,
    fallback_models: Iterable[str],
    *,
    normalize_model: Callable[[str], str],
) -> list[str]:
    cycle: list[str] = []
    for raw_model in [primary_model, *list(fallback_models)]:
        normalized_model = normalize_model(raw_model)
        if not normalized_model or normalized_model in cycle:
            continue
        cycle.append(normalized_model)
    return cycle


def select_model_candidate(
    session: Any,
    candidates: list[dict[str, Any]],
    *,
    message: str,
    single_message_template: str = "",
    no_prompt_message_template: str = "",
    prompt_numbered_choice: Callable[..., dict[str, Any] | None] | None = None,
    prefer_numbered_choice: bool = False,
) -> str:
    if not candidates:
        return ""

    first_model = str(candidates[0].get("model") or "").strip()
    if len(candidates) == 1:
        if single_message_template and first_model:
            print(single_message_template.format(model=first_model))
        return first_model

    if prefer_numbered_choice and prompt_numbered_choice is not None:
        selected = prompt_numbered_choice(session, candidates, message=message)
        if isinstance(selected, dict):
            return str(selected.get("model") or "").strip()
        return ""

    if session is not None and hasattr(session, "choice_selector"):
        selected = session.choice_selector(
            candidates,
            message,
            fields=["printout"],
        )
        if isinstance(selected, dict):
            return str(selected.get("model") or "").strip()
        return ""

    if prompt_numbered_choice is not None:
        selected = prompt_numbered_choice(session, candidates, message=message)
        if isinstance(selected, dict):
            return str(selected.get("model") or "").strip()
        return ""

    if no_prompt_message_template and first_model:
        print(no_prompt_message_template.format(model=first_model))
    return first_model


# ---------------------------------------------------------------------------
# API Keys resource helpers
# ---------------------------------------------------------------------------


def _key_name(*, project_id: str, key_id: str, location: str = "global") -> str:
    text = str(key_id or "").strip()
    if not text or text.startswith("projects/"):
        return text
    return f"projects/{project_id}/locations/{location}/keys/{text}"


def get_key_rows(resource, names: list[str], action_dict=None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in names:
        row = resource.get(name=name, action_dict=action_dict)
        if isinstance(row, dict) and row:
            rows.append(row)
    return rows


def key_row_names(resource, rows: list[dict[str, Any]]) -> list[str]:
    return [name for row in rows if (name := resource.resource_name(row))]


def attach_key_strings(
    resource,
    names: list[str],
    rows: list[dict[str, Any]],
    action_dict=None,
    *,
    require_key_string: bool,
) -> list[dict[str, Any]]:
    base_rows_by_name = {
        resource.resource_name(row): dict(row)
        for row in rows
        if resource.resource_name(row)
    }
    enriched_rows: list[dict[str, Any]] = []
    for name in names:
        merged = dict(base_rows_by_name.get(name) or {})
        if not merged:
            merged["name"] = name
            merged["key_id"] = extract_path_tail(name, default=name)
        key_string = resource.get_key_string(name=name, action_dict=action_dict)
        if require_key_string and not key_string:
            continue
        if key_string:
            merged["key_string"] = key_string
        enriched_rows.append(merged)
    return enriched_rows


class ApiKeysKeysResource:
    TABLE_NAME = "apikeys_keys"
    COLUMNS = [
        "display_name",
        "key_id",
        "uid",
        "state",
        "location",
        "name",
        "create_time",
        "update_time",
        "key_string",
    ]
    SERVICE_LABEL = "API Keys"
    ACTION_RESOURCE_TYPE = "keys"
    LIST_API_NAME = "apikeys.keys.list"
    GET_API_NAME = "apikeys.keys.get"
    GET_KEY_STRING_API_NAME = "apikeys.keys.getKeyString"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import api_keys_v2  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "API Keys enumeration requires the `google-cloud-api-keys` package."
            ) from exc
        self._api_keys_v2 = api_keys_v2
        self.client = api_keys_v2.ApiKeysClient(credentials=session.credentials)

    def _request(self, callback):
        return callback()

    resource_name = staticmethod(resource_name_from_value)
    key_name = staticmethod(_key_name)

    def list(self, *, project_id: str, location: str = "global", action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._api_keys_v2.ListKeysRequest(parent=parent)
            rows = [resource_to_dict(key) for key in self._request(lambda: self.client.list_keys(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str, action_dict=None) -> dict[str, Any] | None:
        if not name:
            return None
        try:
            request = self._api_keys_v2.GetKeyRequest(name=name)
            row = resource_to_dict(self._request(lambda: self.client.get_key(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_name_from_value(row, "name"),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get_key_string(self, *, name: str, action_dict=None) -> str:
        if not name:
            return ""
        try:
            request = self._api_keys_v2.GetKeyStringRequest(name=name)
            response = self._request(lambda: self.client.get_key_string(request=request))
            key_string = str(getattr(response, "key_string", "") or "")
            if key_string:
                record_permissions(
                    action_dict,
                    permissions=self.GET_KEY_STRING_API_NAME,
                    project_id=extract_project_id_from_resource(
                        name,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=str(name or "").strip(),
                )
            return key_string
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.GET_KEY_STRING_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )
            return ""

    def download_key_string(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        key_string = str((row or {}).get("key_string") or "").strip()
        if not key_string:
            return None

        key_id = str((row or {}).get("key_id") or extract_path_tail(resource_name_from_value(row, "name"))).strip() or "api_key"
        destination = Path(
            self.session.get_download_save_path(
                service_name="apikeys",
                project_id=project_id,
                subdirs=["keys"],
                filename=compact_filename_component(f"api_key_{key_id}.txt"),
            )
        )
        destination.write_text(key_string, encoding="utf-8")
        return destination

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str = "global") -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": extract_location_from_resource_name(resource_name_from_value(row, "name")) or location,
                },
                extra_builder=lambda _obj, raw: {
                    "key_id": extract_path_tail(resource_name_from_value(raw, "name")),
                },
            )
