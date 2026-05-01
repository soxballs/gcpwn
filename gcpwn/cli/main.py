from __future__ import annotations

import argparse
import re
import sys
from ast import literal_eval
from pathlib import Path
from types import SimpleNamespace
from typing import List, Optional, Tuple

from gcpwn.cli.module_actions import get_module_action, interact_with_module
from gcpwn.core.console import UtilityTools
from gcpwn.core.db import DataController
from gcpwn.core.output_paths import build_output_path, make_workspace_slug
from gcpwn.core.utils.module_helpers import load_mapping_data


PASSTHROUGH_WORKSPACE_NAME = "PASSTHROUGH"


def create_workspace(dc: DataController, workspace_name: str) -> Optional[int]:
    workspace_name = (workspace_name or "").strip()
    if workspace_name.isdigit():
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Workspace name cannot be numeric-only."
            f" Use a descriptive name (for example: TEST, PROD, LAB).{UtilityTools.RESET}"
        )
        return None

    existing_names = dc.fetch_all_workspace_names() or []
    if workspace_name in existing_names:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] A workspace with that name already exists.{UtilityTools.RESET}")
        return None

    workspace_id = dc.insert_workspace(workspace_name)
    if workspace_id:
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Workspace '{workspace_name}' created.{UtilityTools.RESET}")
    return workspace_id


def create_workspace_flow(
    dc: DataController,
    *,
    startup_silent: bool = False,
) -> None:
    from gcpwn.cli.workspace_instructions import workspace_instructions

    while True:
        workspace_name = input("> New workspace name: ").strip()
        if 1 <= len(workspace_name) <= 80:
            workspace_id = create_workspace(dc, workspace_name)
            if workspace_id:
                workspace_instructions(
                    workspace_id,
                    workspace_name,
                    startup_silent=startup_silent,
                )
                return
        else:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Workspace names must be between 1 and 80 characters."
                f"{UtilityTools.RESET}"
            )


def list_workspaces(workspaces: List[Tuple[int, str]]) -> None:
    print("[*] Found existing sessions:")
    print("  [0] New session")
    for idx, name in workspaces:
        print(f"  [{idx}] {name}")
    print(f"  [{len(workspaces) + 1}] exit")


def choose_workspace(
    workspaces: List[Tuple[int, str]],
    dc: DataController,
    *,
    startup_silent: bool = False,
) -> None:
    from gcpwn.cli.workspace_instructions import workspace_instructions

    list_workspaces(workspaces)
    while True:
        try:
            option = int(input("Choose an option: ").strip())
            break
        except ValueError:
            print("Please enter a valid number.")

    if option == 0:
        create_workspace_flow(dc, startup_silent=startup_silent)
        return
    if option == len(workspaces) + 1:
        raise SystemExit(0)

    workspace_name = dc.get_workspace(option, columns="name")
    if workspace_name:
        workspace_instructions(
            option,
            workspace_name,
            startup_silent=startup_silent,
        )
        return
    print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] No workspace was found with this option. Quitting...{UtilityTools.RESET}")
    raise SystemExit(1)


class PassthroughSession:
    def __init__(
        self,
        *,
        workspace_id: int,
        workspace_name: str,
        project_id: str = "",
    ) -> None:
        self.data_master = DataController()
        self.data_master.create_service_databases()
        self.workspace_id = int(workspace_id)
        self.workspace_name = str(workspace_name or PASSTHROUGH_WORKSPACE_NAME).strip() or PASSTHROUGH_WORKSPACE_NAME
        self.workspace_directory_name = make_workspace_slug(self.workspace_id, self.workspace_name)
        self.project_id = str(project_id or "").strip()
        self.credentials = None
        self.credname = "unauth_passthrough"
        global_project_blob = self.data_master.get_workspace(self.workspace_id, columns="global_project_list")
        if global_project_blob:
            try:
                decoded = literal_eval(str(global_project_blob))
                self.global_project_list = [str(project).strip() for project in decoded if str(project).strip()]
            except Exception:
                self.global_project_list = []
        else:
            self.global_project_list = []
        if self.project_id and self.project_id not in self.global_project_list:
            self.global_project_list.append(self.project_id)
            self.data_master.sync_workspace_projects(self.workspace_id, add=self.global_project_list)
        self.workspace_config = SimpleNamespace(preferred_project_ids=[])

    def close(self) -> None:
        try:
            if self.data_master is not None:
                self.data_master.close()
        except Exception:
            pass

    def choice_prompt(self, prompt: str, regex: str | None = None):
        while True:
            answer = str(input(str(prompt or "")) or "").strip()
            if not regex or re.match(regex, answer):
                return answer
            print("Please provide a valid input.")

    def choice_selector(self, rows_returned=None, custom_message: str = "", fields=None, **_kwargs):
        rows = [row for row in (rows_returned or []) if isinstance(row, dict)]
        if not rows:
            return None

        message = str(custom_message or "Choose an option:").strip()
        if message:
            print(f"[*] {message}")

        normalized_fields = [str(field).strip() for field in (fields or []) if str(field).strip()]
        for index, row in enumerate(rows, start=1):
            if normalized_fields:
                label_parts = [str(row.get(field) or "").strip() for field in normalized_fields if str(row.get(field) or "").strip()]
                label = " | ".join(label_parts)
            else:
                label = (
                    str(row.get("printout") or "").strip()
                    or str(row.get("name") or "").strip()
                    or str(row.get("id") or "").strip()
                    or str(row)
                )
            print(f"  [{index}] {label}")

        while True:
            if len(rows) == 1:
                answer = self.choice_prompt("Choose [1] (or q to cancel): ", regex=r"^(1|q|Q)?$")
                if not answer:
                    answer = "1"
            else:
                answer = self.choice_prompt(
                    f"Choose an option [1-{len(rows)}] (or q to cancel): ",
                    regex=r"^\d+$|^[qQ]$",
                )

            if str(answer).lower() == "q":
                return None
            try:
                choice = int(answer)
            except (TypeError, ValueError):
                print("Please provide a valid input.")
                continue
            if 1 <= choice <= len(rows):
                return rows[choice - 1]
            print("Please provide a valid input.")

    def resolve_output_path(
        self,
        *,
        requested_path: str | Path | None = None,
        service_name: str,
        filename: str = "",
        project_id: str | None = None,
        subdirs: list[str] | None = None,
        target: str = "export",
        mkdir: bool = True,
    ) -> Path:
        if requested_path:
            output_path = Path(requested_path).expanduser()
            if mkdir:
                output_path.parent.mkdir(parents=True, exist_ok=True)
            return output_path

        bucket = "downloads" if str(target or "export").strip().lower() == "download" else "exports"
        scope = project_id or self.project_id or "global"
        return build_output_path(
            self.workspace_directory_name,
            bucket=bucket,
            service_name=service_name,
            filename=filename,
            scope=scope if service_name else None,
            subdirs=subdirs,
            mkdir=mkdir,
        )

    def get_data(self, *args, **kwargs):
        table_name = args[0] if args else kwargs.get("table_name")
        columns = kwargs.get("columns", "*")
        conditions = kwargs.get("conditions")
        if not table_name:
            return []
        return self.data_master.select_rows(
            str(table_name),
            db="service",
            columns=columns,
            conditions=conditions,
            where={"workspace_id": self.workspace_id},
        )

    def insert_data(self, table_name, save_data, only_if_new_columns=None, update_only=False, dont_change=None, if_column_matches=None):
        if only_if_new_columns:
            save_kwargs = {"only_if_missing": only_if_new_columns}
        elif dont_change:
            save_kwargs = {"dont_change": dont_change}
        elif if_column_matches:
            save_kwargs = {"replace_on": if_column_matches}
        else:
            save_kwargs = {}

        if update_only:
            save_data["primary_keys_to_match"]["workspace_id"] = self.workspace_id
            self.data_master.save_service_row(table_name, update_data=save_data)
            return

        save_payload = {key: str(value) for key, value in (save_data or {}).items()}
        save_payload["workspace_id"] = self.workspace_id
        self.data_master.save_service_row(table_name, save_payload, **save_kwargs)

    def insert_actions(self, *args, **kwargs):
        return None


def _iter_module_rows(mapping_payload: dict) -> list[dict]:
    flat_rows = mapping_payload.get("modules")
    if isinstance(flat_rows, list):
        return [dict(row) for row in flat_rows if isinstance(row, dict)]

    rows: list[dict] = []
    for service_entry in mapping_payload.get("services") or []:
        if not isinstance(service_entry, dict):
            continue
        categories = service_entry.get("categories") or {}
        if not isinstance(categories, dict):
            continue
        for category, modules in categories.items():
            if not isinstance(modules, list):
                continue
            for module in modules:
                if not isinstance(module, dict):
                    continue
                row = dict(module)
                row.setdefault("module_category", str(category or "").strip())
                rows.append(row)
    return rows


def _unauth_module_lookup() -> dict[str, str]:
    payload = load_mapping_data("module-mappings.json", kind="json") or {}
    lookup: dict[str, str] = {}
    for row in _iter_module_rows(payload):
        module_name = str(row.get("module_name") or "").strip()
        location = str(row.get("location") or "").strip()
        category = str(row.get("module_category") or "").strip().lower()
        if not module_name or not location:
            continue
        if category != "unauthenticated" and ".unauthenticated." not in location.lower() and not module_name.lower().startswith("unauth_"):
            continue
        lookup[module_name] = location
        lookup[location] = location
    return lookup


def _resolve_unauth_module_path(module_token: str) -> str:
    token = str(module_token or "").strip().replace("/", ".")
    if not token:
        return ""

    lookup = _unauth_module_lookup()
    if token in lookup:
        return lookup[token]

    short_name = token.split(".")[-1]
    if short_name in lookup:
        return lookup[short_name]

    if not get_module_action(token).requires_auth:
        return token

    return ""


def _resolve_passthrough_workspace() -> tuple[int, str]:
    DataController.create_initial_workspace_session_database()
    with DataController() as dc:
        workspaces = dc.get_workspaces() or []
        for workspace_row in workspaces:
            workspace_id = int(workspace_row[0])
            workspace_name = str(workspace_row[1] or "").strip()
            if workspace_name == PASSTHROUGH_WORKSPACE_NAME:
                return workspace_id, workspace_name

        created_workspace_id = dc.insert_workspace(PASSTHROUGH_WORKSPACE_NAME)
        if not created_workspace_id:
            fallback = dc.get_workspaces() or []
            if fallback:
                workspace_id = int(fallback[0][0])
                workspace_name = str(fallback[0][1] or "").strip() or PASSTHROUGH_WORKSPACE_NAME
                return workspace_id, workspace_name
            raise RuntimeError("Unable to create or locate passthrough workspace.")
        return int(created_workspace_id), PASSTHROUGH_WORKSPACE_NAME


def run_unauth_module_passthrough(module_name: str, module_args: list[str], *, project_id: str = "") -> int:
    module_import_path = _resolve_unauth_module_path(module_name)
    if not module_import_path:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Unknown unauth module: {module_name}{UtilityTools.RESET}")
        known = sorted(
            {
                key
                for key in _unauth_module_lookup().keys()
                if not key.startswith("gcpwn.modules.")
            }
        )
        if known:
            print("[*] Available unauth passthrough modules:")
            for name in known:
                print(f"    - {name}")
        return 1

    action = get_module_action(module_import_path)
    if action.requires_auth:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Passthrough mode only supports unauthenticated modules.{UtilityTools.RESET}")
        return 1

    cleaned_args = list(module_args or [])
    if cleaned_args and cleaned_args[0] == "--":
        cleaned_args = cleaned_args[1:]

    workspace_id, workspace_name = _resolve_passthrough_workspace()
    session = PassthroughSession(
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        project_id=project_id,
    )
    if session.project_id:
        print(f"[*] Passthrough project context: {session.project_id}")
    print(f"[*] Passthrough workspace: {workspace_name} (id={workspace_id})")
    print(f"[*] Running unauth module: {module_import_path}")
    try:
        result = interact_with_module(session, module_import_path, cleaned_args)
        return 0 if result == 0 else 1
    finally:
        session.close()


def main() -> None:
    raw_argv = list(sys.argv[1:])

    passthrough_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    passthrough_parser.add_argument(
        "--silent",
        action="store_true",
        help="Start GCPwn without printing the initial help banner.",
    )
    passthrough_parser.add_argument(
        "--module",
        dest="module_name",
        help=(
            "Run an unauthenticated module directly (non-interactive startup). "
            "Accepts short module name (for example: unauth_apikey_enum_all_scopes) "
            "or full import path."
        ),
    )
    passthrough_parser.add_argument(
        "--project-id",
        dest="project_id",
        default="",
        help=(
            "Optional project context for passthrough mode. "
            "Useful for unauth modules that derive target URLs from a project ID."
        ),
    )
    passthrough_args, unknown_args = passthrough_parser.parse_known_args(raw_argv)

    if passthrough_args.module_name:
        raise SystemExit(
            run_unauth_module_passthrough(
                passthrough_args.module_name,
                list(unknown_args),
                project_id=passthrough_args.project_id,
            )
        )

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Start GCPwn without printing the initial help banner.",
    )
    parser.add_argument(
        "--module",
        dest="module_name",
        help=(
            "Run an unauthenticated module directly (non-interactive startup). "
            "Accepts short module name (for example: unauth_apikey_enum_all_scopes) "
            "or full import path."
        ),
    )
    parser.add_argument(
        "--project-id",
        dest="project_id",
        default="",
        help=(
            "Optional project context for passthrough mode. "
            "Useful for unauth modules that derive target URLs from a project ID."
        ),
    )
    args = parser.parse_args(raw_argv)

    DataController.create_initial_workspace_session_database()
    with DataController() as dc:
        workspaces = dc.get_workspaces()
        if len(workspaces) == 0:
            print("[*] No workspaces were detected. Please provide the name for your first workspace below.")
            create_workspace_flow(dc, startup_silent=args.silent)
            return
        choose_workspace(workspaces, dc, startup_silent=args.silent)


if __name__ == "__main__":
    main()
