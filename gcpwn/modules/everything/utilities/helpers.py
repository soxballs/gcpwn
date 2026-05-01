from __future__ import annotations

import datetime
from collections import defaultdict
from functools import lru_cache
from typing import Any, Callable, Iterable

import pandas as pd

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.iam_simplifier import create_simplified_hierarchy_permissions
from gcpwn.core.utils.module_helpers import parse_json_value, parse_string_list



def load_permission_rules():
    permission_rules = load_permission_mapping()
    single_role_dict: dict[str, dict[str, Any]] = {}
    multi_role_dict: dict[str, list[dict[str, Any]]] = {}

    main_permissions = {
        str(rule.get("main_permission") or "").strip()
        for rule in permission_rules
        if str(rule.get("main_permission") or "").strip() not in {"", "None"}
    }

    for main_permission in sorted(main_permissions):
        primary_rule = next(
            (rule for rule in permission_rules if str(rule.get("main_permission") or "").strip() == main_permission),
            None,
        )
        if not primary_rule:
            continue

        related_rules = [rule for rule in permission_rules if main_permission in str(rule.get("id") or "")]
        if len(related_rules) <= 1:
            single_role_dict[main_permission] = primary_rule
            continue
        multi_role_dict[main_permission] = related_rules

    return single_role_dict, multi_role_dict

            
def generate_summary_of_permission_vulns(
    current_permissions,
    session,
    check_permission_vulns=False,
    snapshot = False,
    first_run=False,
    output_file=None,
    csv=False,
    txt=False,
    stdout=False
):  
    permissions_payload = dict(current_permissions or {})
    credname = str(permissions_payload.pop("credname", "Unknown"))
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    output = output_file if output_file else "Vuln_Permission_Summary" if check_permission_vulns else f"Snapshots/Permission_Summary_{credname}_{timestamp}" if snapshot else "Permission_Summary" 
    
    txt_output = UtilityTools.get_save_filepath(session.workspace_directory_name,f"{output}.txt", "Reports") if txt else None
    csv_output = UtilityTools.get_save_filepath(session.workspace_directory_name,f"{output}.csv", "Reports") if csv else None

    csv_rows = []
    formatted_string = ""

    if stdout or txt:
        formatted_string = f"[******] Permission Summary for {credname} [******]\n"
    
    if permissions_payload:

        if check_permission_vulns:

            perm_output = populate_permission_vulnerabilities(permissions_payload)
            
            if perm_output:
                direct_issues = perm_output["direct"]
                for issue in direct_issues:
                    row = {
                        "issue_id": issue["issue_id"],
                        "credname": credname,
                        "issue_title": issue["issue_title"],
                        "issue_type": "PERMISSION_DIRECT",
                        "issue_permission": issue["permission"],
                        "permission_mappings": issue["permission_mappings"],
                        "asset_type": issue["resource_type"],
                        "asset_name": issue["resource_names"],
                        "asset_project_id": issue["project_id"]
                    }
                    csv_rows.append(row)
                    formatted_string += (
                        f"\nIssue ID: {issue['issue_id']}\n"
                        f"Issue Title: {issue['issue_title']}\n"
                        f"Issue Impacted Permission: {issue['permission']}\n"
                        f"Issue Resource Type: {issue['resource_type']}\n"
                        f"Issue Resource Name: {issue['resource_names']}\n"
                        f"Issue Project Id: {issue['project_id']}\n"
                        f"Issue Permission Mappings: {issue['permission_mappings']}\n"
                    )
        else:

            # Get list of permissions to bold Red
            permission_map = load_permission_mapping()
            permissions_list = [data['permission'] for data in permission_map if data.get('main_permission') != "None"]

            # If stdout/txt make formatted string
            if stdout or txt:
                for resource_key, gen_perms in permissions_payload.items():
                    if resource_key in ['project_actions_allowed', 'folder_actions_allowed', 'organization_actions_allowed']:
                        base_permissions = {
                            'project_actions_allowed': "Project",
                            'folder_actions_allowed': "Folder",
                            'organization_actions_allowed': "Organization"
                        }.get(resource_key, "")
                        
                        section_content = ""
                        
                        asset_names = sorted(gen_perms.keys())

                        for asset_name in asset_names:
                            permission_list = gen_perms[asset_name]
                            asset_content = f"  - {asset_name}\n"
                            for permission in sorted(permission_list):
                                asset_content += (
                                    f"{UtilityTools.RED}{UtilityTools.BOLD}    - {permission}{UtilityTools.RESET}\n"
                                    if permission in permissions_list or ".setIamPolicy" in permission
                                    else f"    - {permission}\n"
                                )
                            section_content += asset_content

                        if section_content:
                            formatted_string += f"- {base_permissions} Permissions\n{section_content}"
                    else:
                        header = f"- {resource_key.replace('_', ' ').title()} Permissions\n"
                        section_content = ""

                        for project_id, permission_list in gen_perms.items():
                            project_asset_string = ""
                            for permission_name, asset_descriptions in permission_list.items():
                                # Collect asset names and sort them alphabetically
                                sorted_assets = sorted(
                                    (asset_name, asset_type)
                                    for asset_type, asset_list in asset_descriptions.items()
                                    for asset_name in asset_list if asset_list
                                )
                                permissions_asset_string = "".join(
                                    f"      - {asset_name} ({asset_type})\n"
                                    for asset_name, asset_type in sorted_assets
                                )
                                if permissions_asset_string:
                                    project_asset_string += (
                                        f"{UtilityTools.RED}{UtilityTools.BOLD}    - {permission_name}{UtilityTools.RESET}\n{permissions_asset_string}"
                                        if permission_name in permissions_list or ".setIamPolicy" in permission_name
                                        else f"    - {permission_name}\n{permissions_asset_string}"
                                    )
                            if project_asset_string:
                                section_content += f"  - {project_id}\n{project_asset_string}"

                        if section_content:
                            formatted_string += header + section_content

            if csv:
                for resource_key, gen_perms in permissions_payload.items():
                    if resource_key in ['project_actions_allowed', 'folder_actions_allowed', 'organization_actions_allowed']:
                        base_permissions = {
                            'project_actions_allowed': "Project",
                            'folder_actions_allowed': "Folder",
                            'organization_actions_allowed': "Organization"
                        }.get(resource_key, "")
                        for asset_name, permissions in gen_perms.items():
                            
                            project_id = asset_name if resource_key == 'project_actions_allowed' else "N/A"

                            for permission in permissions:
                                event = {
                                    "Credname": credname,
                                    "Permission": permission,
                                    "Asset Type": base_permissions,
                                    "Asset Name": asset_name,
                                    "Project_ID": project_id,
                                    "Flagged": "True" if permission in permissions_list or ".setIamPolicy" in permission else "False"
                                }
                                csv_rows.append(event)
                    else:
                        for project_id, permission_list in gen_perms.items():
                            for permission_name, asset_descriptions in permission_list.items():
                                for asset_type, asset_list in asset_descriptions.items():
                                    for asset_name in asset_list:
                                        event = {
                                            "Credname": credname,
                                            "Permission": permission_name,
                                            "Asset Type": asset_type,
                                            "Asset Name": asset_name,
                                            "Project_ID": project_id,
                                            "Flagged": "True" if permission_name in permissions_list or ".setIamPolicy" in permission_name else "False"
                                        }
                                        csv_rows.append(event)

    if stdout:
        print(formatted_string)

    if txt and txt_output:
        mode = "w" if first_run else "a"
        with open(txt_output, mode) as txt_file:
            txt_file.write(formatted_string)

    if csv and csv_output:
        df = pd.DataFrame(csv_rows)
        mode = "w" if first_run else "a"
        header = first_run  # Write header only if it's the first run
        df.to_csv(csv_output, mode=mode, header=header, index=False)


def populate_permission_vulnerabilities(all_credname_resources_dict):
   
    single_role_dict, multi_role_dict = load_permission_rules()

    existing_vulns = {
        "direct": []
    }

    def extend_vulns(findings):
        if findings:
            existing_vulns["direct"].extend(findings)

    extend_vulns(permission_only_single_permission(single_role_dict, all_credname_resources_dict))
    extend_vulns(permission_only_multi_permission(multi_role_dict, all_credname_resources_dict))

    return existing_vulns


def permission_only_single_permission(single_role_dict, all_resources_dict):
    rules_by_permission = {
        str(rule.get("permission") or "").strip(): (issue_id, rule)
        for issue_id, rule in (single_role_dict or {}).items()
        if str(rule.get("permission") or "").strip()
    }
    if not rules_by_permission:
        return []

    type_map = {
        "organization_actions_allowed": "organization",
        "folder_actions_allowed": "folder",
        "project_actions_allowed": "project",
    }
    vuln_ids = []

    def _append_finding(
        *,
        permission_name: str,
        resource_type: str,
        resource_name: str | list[str],
        project_id: str | None = None,
    ) -> None:
        match = rules_by_permission.get(str(permission_name or "").strip())
        if not match:
            return
        issue_id, rule = match
        vuln_ids.append(
            {
                "issue_id": issue_id,
                "issue_title": rule["issue"],
                "permission": permission_name,
                "resource_type": resource_type,
                "permission_mappings": "N/A",
                "project_id": project_id or "N/A",
                "resource_names": resource_name,
            }
        )

    for asset_category, all_asset_information in (all_resources_dict or {}).items():
        if asset_category in type_map:
            mapped_resource_type = type_map[asset_category]
            for resource_name, permissions in (all_asset_information or {}).items():
                inferred_project_id = resource_name if asset_category == "project_actions_allowed" else None
                for permission_name in permissions or []:
                    _append_finding(
                        permission_name=permission_name,
                        resource_type=mapped_resource_type,
                        resource_name=resource_name,
                        project_id=inferred_project_id,
                    )
            continue

        for project_id, specific_resource_info in (all_asset_information or {}).items():
            for permission_name, asset_types in (specific_resource_info or {}).items():
                for asset_type, all_affected_resources in (asset_types or {}).items():
                    _append_finding(
                        permission_name=permission_name,
                        resource_type=asset_type,
                        resource_name=all_affected_resources,
                        project_id=project_id,
                    )
    return vuln_ids

def permission_only_multi_permission(multi_role_dict, all_resources_dict):
    vuln_ids = []

    for _, rules in (multi_role_dict or {}).items():
        if not rules:
            continue

        main_rule = next(
            (
                rule
                for rule in rules
                if str(rule.get("main_permission") or "") != "None"
                and all(str(rule.get("main_permission") or "") in str(inner.get("id") or "") for inner in rules)
            ),
            None,
        )
        if not main_rule:
            continue

        issue_id = str(main_rule.get("main_permission") or "")
        issue_title = str(main_rule.get("issue") or "")
        required_permission = str(main_rule.get("permission") or "")
        if not required_permission:
            continue
        sibling_permissions = [
            str(rule.get("permission") or "")
            for rule in rules
            if str(rule.get("permission") or "") and str(rule.get("permission") or "") != required_permission
        ]

        for asset_type, all_asset_information in (all_resources_dict or {}).items():
            if asset_type in ["organization_actions_allowed", "folder_actions_allowed", "project_actions_allowed"]:
                for resource_name, permissions in (all_asset_information or {}).items():
                    if required_permission not in (permissions or []):
                        continue

                    impacted = [
                        {"permission": required_permission, "asset_names": [resource_name], "asset_type": asset_type}
                    ]
                    for permission in sibling_permissions:
                        permissions_summary = check_if_permission_exists(
                            all_resources_dict,
                            permission,
                            org_name_to_check=resource_name if asset_type == "organization_actions_allowed" else None,
                            folder_name_to_check=resource_name if asset_type == "folder_actions_allowed" else None,
                            project_id_to_check=resource_name if asset_type == "project_actions_allowed" else None,
                        )
                        if not permissions_summary:
                            impacted = []
                            break
                        impacted.append(permissions_summary)

                    if impacted:
                        vuln_ids.append(
                            {
                                "issue_id": issue_id,
                                "issue_title": issue_title,
                                "permission": required_permission,
                                "permission_mappings": impacted,
                                "project_id": "N/A",
                                "resource_names": "N/A",
                                "resource_type": "N/A",
                            }
                        )
                continue

            for project_id, specific_resource_info in (all_asset_information or {}).items():
                for permission_name, asset_types in (specific_resource_info or {}).items():
                    if permission_name != required_permission:
                        continue
                    for discovered_asset_type, all_affected_resources in (asset_types or {}).items():
                        impacted = [
                            {
                                "permission": permission_name,
                                "asset_names": all_affected_resources,
                                "asset_type": discovered_asset_type,
                            }
                        ]
                        for permission in sibling_permissions:
                            permissions_summary = check_if_permission_exists(
                                all_resources_dict,
                                permission,
                                project_id_to_check=project_id,
                            )
                            if not permissions_summary:
                                impacted = []
                                break
                            impacted.append(permissions_summary)
                        if not impacted:
                            continue

                        updated_permissions = update_permission_groupings(impacted)
                        if not updated_permissions:
                            continue
                        vuln_ids.append(
                            {
                                "issue_id": issue_id,
                                "issue_title": issue_title,
                                "permission": permission_name,
                                "permission_mappings": updated_permissions,
                                "project_id": "N/A",
                                "resource_names": "N/A",
                                "resource_type": "N/A",
                            }
                        )
    return vuln_ids

def check_if_permission_exists(all_resources_dict, permission, project_id_to_check=None, folder_name_to_check=None, org_name_to_check=None):
    scoped_targets = {
        "project_actions_allowed": project_id_to_check,
        "folder_actions_allowed": folder_name_to_check,
        "organization_actions_allowed": org_name_to_check,
    }
    for asset_type, all_asset_information in (all_resources_dict or {}).items():
        target_resource_name = scoped_targets.get(asset_type)
        if target_resource_name is not None:
            permissions = (all_asset_information or {}).get(target_resource_name, [])
            if permission in (permissions or []):
                return {"permission": permission, "asset_type": asset_type, "asset_names": [target_resource_name]}
            continue

        for project_id, specific_resource_info in (all_asset_information or {}).items():
            if project_id_to_check != project_id:
                continue
            for permission_name, asset_types in (specific_resource_info or {}).items():
                if permission != permission_name:
                    continue
                for discovered_asset_type, all_affected_resources in (asset_types or {}).items():
                    return {
                        "permission": permission_name,
                        "asset_type": discovered_asset_type,
                        "asset_names": all_affected_resources,
                    }
    return None

def update_permission_groupings(each_permission_details):

    # Organize permissions by asset type and find common assets
    permissions_by_type = defaultdict(list)
    common_assets = defaultdict(set)

    for permission_detail in each_permission_details:
        asset_type = permission_detail["asset_type"]
        permissions_by_type[asset_type].append(permission_detail)
        if asset_type in common_assets:
            common_assets[asset_type].intersection_update(permission_detail["asset_names"])
        else:
            common_assets[asset_type] = set(permission_detail["asset_names"])

    # Check if there are no shared resources for any asset type
    if all(not assets for assets in common_assets.values()):
        return None

    # Update permissions to include only common assets
    for asset_type, perms in permissions_by_type.items():
        common_assets_set = common_assets[asset_type]
        for perm in perms:
            perm["asset_names"] = list(common_assets_set)

    return each_permission_details


def generate_summary_of_roles_or_vulns(
    session,
    member,
    roles_and_assets,
    issue_label=None,
    issue_type=None,
    snapshot = False,
    check_role_vulns=False,
    first_run=False,
    output_file=None,
    csv=False,
    txt=False,
    stdout=False
):
  
    def formatted_asset_name(asset_official_name, parent_id=None, asset_common_name=None, asset_project_id=None):
        formatted_string = f"  - \"{asset_official_name}\""
        if asset_type not in ["org", "folder", "project"]:
            formatted_string += f" (in {parent_id})"
        elif asset_common_name != "N/A":
            formatted_string += f" - {asset_common_name}"
        if asset_type == "project" and asset_project_id != "N/A":
            formatted_string += f" ({asset_project_id})"
        return formatted_string + "\n"

    def formatted_member_header():
        summary_type = "Vuln Summary" if check_role_vulns else "Summary"
        return f"{UtilityTools.BOLD}\n[******] {summary_type} for {member} [******]\n{UtilityTools.RESET}"

    def add_csv_row(issue=None):
        issue_direct_roles = "N/A"
        issue_inherited_roles = "N/A"
        if issue:
            if issue["issue_type"] == "IAM_DIRECT":
                issue_direct_roles = issue.get("role", "N/A")
            elif issue["issue_type"] == "IAM_INHERITED":
             
                issue_inherited_roles = issue.get("role", "N/A")

        row = {
            "issue_id": issue.get("issue_id", "0") if issue else "0",
            "member": member,
            "issue_title": issue.get("issue_title", issue_label) if issue else "N/A",
            "issue_type": issue.get("issue_type", issue_type) if issue else "N/A",
            "issue_permission": issue.get("permission", "N/A") if issue else "N/A",
            "issue_direct_roles": issue_direct_roles,
            "issue_inherited_roles": issue_inherited_roles,
            "issue_ancestor": issue.get("ancestor", issue_type) if issue else "N/A",
            "asset_type": asset_type,
            "asset_name": asset_official_name,
            "asset_common_name": asset_common_name,
            "asset_project_id": asset_project_id,
            "resource_owner": parent_id,
            "asset_all_direct_permissions": str(all_direct_roles),
            "asset_all_inherited_permissions": str(all_inherited_roles)
        }
        csv_rows.append(row)

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    output = output_file if output_file else "Vuln_Roles_Summary"  if check_role_vulns else f"Snapshots/Roles_Summary_{member}_{timestamp}" if snapshot else "Roles_Summary" 
    txt_output = UtilityTools.get_save_filepath(session.workspace_directory_name, f"{output}.txt", "Reports") if txt else None
    csv_output = UtilityTools.get_save_filepath(session.workspace_directory_name, f"{output}.csv", "Reports") if csv else None
    csv_rows = []

    if stdout or txt:
        formatted_string = formatted_member_header()

    asset_headers = {
        "org": "Organization Summary\n",
        "project": "Project Summary\n",
        "folder": "Folder Summary\n",
        "bucket": "Cloud Storage Summary\n",
        "cloudfunction": "Cloud Function Summary\n",
        "computeinstance": "Cloud Compute Summary\n",
        "saaccounts": "Service Accounts Summary\n",
        "secrets": "Secret Manager Summary\n",
    }

    for asset_type, all_assets in roles_and_assets.items():

        roles_exist = False
        asset_type_header = asset_headers.get(asset_type, "")

        for asset_official_name, asset_details in all_assets.items():

            parent_id = asset_details["parent_id"]
            asset_project_id = parent_id if asset_type == "project" else "N/A"
            asset_common_name = asset_details["common_name"] if asset_type in ["org", "project", "folder"] else "N/A"
            all_direct_roles, all_inherited_roles = asset_details["Direct Permissions"], asset_details["Inherited Permissions"]

            if check_role_vulns:

                if stdout or txt:
                    formatted_string += asset_type_header
                    formatted_string += formatted_asset_name(asset_official_name, parent_id, asset_common_name, asset_project_id)

                    if issue_type and issue_label:
                        formatted_string += (
                            f"    - 0:{issue_type}:{issue_label} \n"
                            f"      - Impacted Direct Role(s): {str(all_direct_roles) if all_direct_roles else 'N/A'} \n"
                            f"      - Impacted Inherited Role(s): {str(all_inherited_roles) if all_inherited_roles else 'N/A'} \n"
                        )
                    else:
                        
                        issues = populate_vulnerabilities(session, all_direct_roles, all_inherited_roles)
                        if issues:
                            for issue in issues["direct"] + issues["inherited"]:
                                issue_type = "IAM_INHERITED" if issue in issues["inherited"] else "IAM_DIRECT"
                                formatted_string += (
                                    f"    - {issue['issue_id']}:{issue_type}:{issue['permission']}:{issue['issue_title']} \n"
                                    f"      - Impacted {issue_type.replace('IAM_', '')} Role(s): {issue['role']} \n"
                                )

                if csv:
                    if issue_type and issue_label:
                        add_csv_row()
                    
                    else:
                        issues = populate_vulnerabilities(session, all_direct_roles, all_inherited_roles)
                        if issues:
                          

                            for issue in issues["direct"] + issues["inherited"]:
                                issue_type = "IAM_INHERITED" if issue in issues["inherited"] else "IAM_DIRECT"
                                issue["issue_type"] = issue_type
                                add_csv_row(issue)
            else:
                if stdout or txt:
                    if not roles_exist:
                        formatted_string += asset_type_header
                        roles_exist = True

                    formatted_string += formatted_asset_name(asset_official_name, parent_id, asset_common_name, asset_project_id)

                    for role in sorted(all_direct_roles):
                        formatted_string += f"    - {role}\n"

                        
                    filtered_inherited_roles = [
                        {'ancestor': item['ancestor'], 'roles': item['roles'] - all_direct_roles}
                        for item in all_inherited_roles
                        if item['roles'] - all_direct_roles
                    ]
                
                    for item in filtered_inherited_roles:
                        ancestor, inherited_roles = item["ancestor"], item["roles"]
                        if inherited_roles:
                            for role in sorted(inherited_roles):
                                if any(x in ancestor for x in ["projectEditor", "projectViewer", "projectOwner"]):
                                    ending = ancestor
                                else:
                                    ending = f" (Inherited From {ancestor})"
                                formatted_string = formatted_string +  f"    - {role} " + ending + "\n"
                           
                if csv:
                    row = {
                        "member": member,
                        "asset_type": asset_type,
                        "asset_name": asset_official_name,
                        "asset_common_name": asset_common_name,
                        "asset_project_id": asset_project_id,
                        "resource_owner": parent_id,
                        "asset_direct_permissions": str(all_direct_roles),
                        "asset_inherited_permissions": str(all_inherited_roles),
                    }
                    csv_rows.append(row)

    if stdout:
        print(formatted_string)

    if txt:
        mode = "w" if first_run else "a"
        with open(txt_output, mode) as txt_file:
            txt_file.write(formatted_string)

    if csv:
        df = pd.DataFrame(csv_rows)
        mode = "w" if first_run else "a"
        header = first_run
        df.to_csv(csv_output, mode=mode, header=header, index=False)


@lru_cache(maxsize=1)
def load_permission_mapping():
    # Deprecated with analyze_vulns disablement; placeholder until replaced by
    # OpenGraph rule-driven vulnerability analysis.
    return []


def _role_permissions(session, role_name: str) -> set[str]:
    role = str(role_name or "").strip()
    if not role:
        return set()
    rows = session.get_data("iam_roles", columns=["included_permissions"], conditions=f'name = "{role}"') or []
    if not rows:
        return set()
    value = rows[0].get("included_permissions") if isinstance(rows[0], dict) else None
    return set(
        parse_string_list(
            value,
            allow_json=False,
            allow_python_literal=True,
            fallback_to_single=True,
        )
    )


def _is_custom_role_name(role_name: str) -> bool:
    token = str(role_name or "")
    return token.startswith("projects/") or token.startswith("organizations/")


def _matched_permission_for_role(
    *,
    session,
    role_name: str,
    required_roles: set[str],
    required_permission: str,
    alternate_roles: set[str],
    alternate_permission: str | None,
    custom_permissions_cache: dict[str, set[str]],
) -> str | None:
    role_token = str(role_name or "")
    if _is_custom_role_name(role_token):
        permissions = custom_permissions_cache.get(role_token)
        if permissions is None:
            permissions = _role_permissions(session, role_token)
            custom_permissions_cache[role_token] = permissions
        if required_permission in permissions:
            return required_permission
        if alternate_permission and alternate_permission in permissions:
            return alternate_permission

    if role_token in required_roles:
        return required_permission
    if alternate_permission and role_token in alternate_roles:
        return alternate_permission
    return None


def _single_role_findings(
    session,
    *,
    role_name: str,
    single_role_dict,
    ancestor: str = "N/A",
    custom_permissions_cache: dict[str, set[str]] | None = None,
):
    findings = []
    role_token = str(role_name or "")
    permissions_of_role = None
    if _is_custom_role_name(role_token):
        cache = custom_permissions_cache if custom_permissions_cache is not None else {}
        permissions_of_role = cache.get(role_token)
        if permissions_of_role is None:
            permissions_of_role = _role_permissions(session, role_token)
            cache[role_token] = permissions_of_role

    for issue_id, rule in single_role_dict.items():
        permission = rule["permission"]
        if permissions_of_role is not None:
            matched = permission in permissions_of_role
        else:
            matched = role_token in rule.get("roles", [])
        if matched:
            findings.append(
                {
                    "issue_id": issue_id,
                    "issue_title": rule["issue"],
                    "role": role_token,
                    "permission": permission,
                    "ancestor": ancestor,
                }
            )
    return findings


def multi_role_check(
    session,
    testing_roles_list,
    multi_role_dict,
    inherited=False,
    custom_permissions_cache: dict[str, set[str]] | None = None,
):
    vuln_ids = []
    permissions_cache = custom_permissions_cache if custom_permissions_cache is not None else {}

    for issue_id, rules in multi_role_dict.items():
        issue_title = next((rule.get("issue") for rule in rules if issue_id == rule.get("main_permission")), None) or (
            rules[0].get("issue") if rules else "N/A"
        )

        ancestors = []
        impacted_roles_and_permissions = []
        issue_applies = True

        for rule in rules:
            required_permission = str(rule.get("permission") or "")
            required_roles = set(rule.get("roles") or [])

            alternate_permission = None
            alternate_roles: set[str] = set()
            alternate_key = str(rule.get("alternate") or "None")
            if alternate_key != "None":
                alternate_rule = next((inner for inner in rules if inner.get("permission") == alternate_key), None)
                if alternate_rule:
                    alternate_permission = str(alternate_rule.get("permission") or "")
                    alternate_roles = set(alternate_rule.get("roles") or [])

            rule_matched = False
            if inherited:
                for role_information in testing_roles_list or []:
                    ancestor = str(role_information.get("ancestor") or "")
                    for role_name in role_information.get("roles") or []:
                        matched_permission = _matched_permission_for_role(
                            session=session,
                            role_name=role_name,
                            required_roles=required_roles,
                            required_permission=required_permission,
                            alternate_roles=alternate_roles,
                            alternate_permission=alternate_permission,
                            custom_permissions_cache=permissions_cache,
                        )
                        if matched_permission:
                            impacted_roles_and_permissions.append(
                                {"role": role_name, "permission": matched_permission, "ancestor": ancestor}
                            )
                            ancestors.append(ancestor)
                            rule_matched = True
                            break
                    if rule_matched:
                        break
            else:
                for role_name in testing_roles_list or []:
                    matched_permission = _matched_permission_for_role(
                        session=session,
                        role_name=role_name,
                        required_roles=required_roles,
                        required_permission=required_permission,
                        alternate_roles=alternate_roles,
                        alternate_permission=alternate_permission,
                        custom_permissions_cache=permissions_cache,
                    )
                    if matched_permission:
                        impacted_roles_and_permissions.append({"role": role_name, "permission": matched_permission})
                        rule_matched = True
                        break

            if not rule_matched:
                issue_applies = False
                break

        if issue_applies:
            vuln_entry = {
                "issue_id": issue_id,
                "issue_title": issue_title,
                "role": impacted_roles_and_permissions,
                "permission": "N/A",
                "ancestor": ancestors if inherited else "N/A",
            }
            vuln_ids.append(vuln_entry)

    return vuln_ids


def populate_vulnerabilities(session, direct_roles, inherited_roles_dicts):
    single_role_dict, multi_role_dict = load_permission_rules()
    existing_vulns = {"direct": [], "inherited": []}
    custom_permissions_cache: dict[str, set[str]] = {}

    for role_name in direct_roles or []:
        existing_vulns["direct"].extend(
            _single_role_findings(
                session,
                role_name=role_name,
                single_role_dict=single_role_dict,
                custom_permissions_cache=custom_permissions_cache,
            )
        )

    if direct_roles:
        existing_vulns["direct"].extend(
            multi_role_check(
                session,
                direct_roles,
                multi_role_dict,
                custom_permissions_cache=custom_permissions_cache,
            )
        )

    for role_information in inherited_roles_dicts or []:
        ancestor = str(role_information.get("ancestor") or "N/A")
        for role_name in role_information.get("roles") or []:
            existing_vulns["inherited"].extend(
                _single_role_findings(
                    session,
                    role_name=role_name,
                    single_role_dict=single_role_dict,
                    ancestor=ancestor,
                    custom_permissions_cache=custom_permissions_cache,
                )
            )

    if inherited_roles_dicts:
        existing_vulns["inherited"].extend(
            multi_role_check(
                session,
                inherited_roles_dicts,
                multi_role_dict,
                inherited=True,
                custom_permissions_cache=custom_permissions_cache,
            )
        )

    return existing_vulns


def policy_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    parsed = parse_json_value(raw, default=None)
    return parsed if isinstance(parsed, dict) else {}


def canonical_iam_member(member: str) -> str:
    token = str(member or "").strip()
    if not token:
        return ""
    lowered = token.lower()
    if lowered == "all_users":
        return "allUsers"
    if lowered == "all_authenticated_users":
        return "allAuthenticatedUsers"
    if ":" not in token:
        return token

    prefix, rest = token.split(":", 1)
    mapped = {
        "service_account": "serviceAccount",
        "serviceaccount": "serviceAccount",
        "project_owner": "projectOwner",
        "projectowner": "projectOwner",
        "project_editor": "projectEditor",
        "projecteditor": "projectEditor",
        "project_viewer": "projectViewer",
        "projectviewer": "projectViewer",
    }.get(prefix.lower())

    return f"{mapped}:{rest}" if mapped else token


def iter_member_roles_from_policy(policy: dict[str, Any]) -> Iterable[tuple[str, list[str]]]:
    by_member = policy.get("by_member")
    if isinstance(by_member, dict):
        for member, details in by_member.items():
            member_token = canonical_iam_member(str(member))
            if not member_token:
                continue
            roles = details.get("roles") if isinstance(details, dict) else []
            if not isinstance(roles, list):
                roles = [roles]
            normalized_roles = sorted({str(role).strip() for role in roles if str(role).strip()})
            if normalized_roles:
                yield member_token, normalized_roles
        return

    collapsed: dict[str, set[str]] = {}
    for binding in policy.get("bindings") or []:
        if not isinstance(binding, dict):
            continue
        role = str(binding.get("role") or "").strip()
        if not role:
            continue
        members = binding.get("members") or []
        if not isinstance(members, list):
            members = [members]
        for member in members:
            member_token = canonical_iam_member(member)
            if member_token:
                collapsed.setdefault(member_token, set()).add(role)

    for member, roles in collapsed.items():
        normalized_roles = sorted({str(role).strip() for role in roles if str(role).strip()})
        if normalized_roles:
            yield member, normalized_roles


def flatten_iam_allow_policies(
    allow_rows: Iterable[dict[str, Any]] | None,
    *,
    asset_name: str | None = None,
    type_of_asset: str | None = None,
    display_name_lookup: Callable[[str], str] | None = None,
) -> list[dict[str, str]]:
    target_asset = str(asset_name or "").strip()
    target_type = str(type_of_asset or "").strip()
    simplified = create_simplified_hierarchy_permissions(
        allow_rows or [],
        include_inheritance=False,
        normalize_member=canonical_iam_member,
        is_convenience_member=lambda member: str(member or "").strip().startswith(
            ("projectViewer:", "projectEditor:", "projectOwner:")
        ),
    )

    out: list[dict[str, str]] = []
    for row in simplified.get("flattened_member_rows") or []:
        resource_name = str(row.get("name") or "").strip()
        resource_type = str(row.get("type") or "").strip()
        project_id = str(row.get("project_id") or "").strip()
        if not resource_name or not resource_type:
            continue
        if target_asset and resource_name != target_asset:
            continue
        if target_type and resource_type != target_type:
            continue

        display_name = str(row.get("display_name") or "").strip()
        if display_name_lookup and resource_type in {"org", "folder", "project"}:
            display_name = str(display_name_lookup(resource_name) or "").strip()

        out.append(
            {
                "member": str(row.get("member") or "").strip(),
                "project_id": project_id,
                "name": resource_name,
                "display_name": display_name,
                "type": resource_type,
                "roles": str(row.get("roles") or "[]"),
            }
        )
    return out


def split_members_by_kind(members: Iterable[str]) -> tuple[list[str], list[str]]:
    members_set = {str(m).strip() for m in (members or []) if str(m or "").strip()}
    convenience = sorted(m for m in members_set if m.startswith(("projectViewer:", "projectEditor:", "projectOwner:")))
    normal = sorted(members_set - set(convenience))
    return convenience, normal


def add_convenience_roles(data_dict: dict[str, Any], convenience_summary: dict[str, Any]) -> None:
    for bucket, perms_by_project in (convenience_summary or {}).items():
        if bucket not in data_dict.get("bucket", {}):
            continue
        for project_name, roles in (perms_by_project or {}).items():
            proj_data = data_dict.get("project", {}).get(project_name)
            if not proj_data or "Direct Permissions" not in proj_data:
                continue
            direct_roles = proj_data["Direct Permissions"]
            for role in ("viewer", "editor", "owner"):
                if roles.get(role) and f"roles/{role}" in direct_roles:
                    data_dict["bucket"][bucket]["Inherited Permissions"].append(
                        {
                            "ancestor": f"project{role.capitalize()} Points to {project_name}",
                            "roles": roles[role],
                        }
                    )


def consolidate_convenience_roles(
    session,
    convenience_members: list[str],
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    all_convenience_summary: dict[str, Any] = {}
    member_data_dict: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings or []:
        member = binding.get("member")
        if not member:
            continue
        member_data_dict.setdefault(str(member), []).append(binding)

    for member in convenience_members or []:
        for data in member_data_dict.get(member, []):
            full_resource_name = data["name"]
            project_id = member.split(":", 1)[1]
            project_name = session.get_project_name(project_id)
            project_name = project_name[0]["name"] if project_name else "Unknown"
            roles = set(
                parse_string_list(
                    data["roles"],
                    allow_json=True,
                    allow_python_literal=True,
                    fallback_to_single=True,
                )
            )
            role_type = (
                "owner"
                if member.startswith("projectOwner:")
                else "editor" if member.startswith("projectEditor:") else "viewer"
            )

            all_convenience_summary.setdefault(full_resource_name, {}).setdefault(
                project_name,
                {"viewer": set(), "editor": set(), "owner": set()},
            )[role_type].update(roles)

    return all_convenience_summary


def build_roles_and_assets_for_member(
    session,
    *,
    member: str,
    bindings: list[dict[str, Any]],
    convenience_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    project_name_cache: dict[str, str] = {}

    def _project_name(project_id: str) -> str:
        token = str(project_id or "").strip()
        if token in project_name_cache:
            return project_name_cache[token]
        response = session.get_project_name(token)
        resolved = response[0]["name"] if response else "Unknown"
        project_name_cache[token] = resolved
        return resolved

    member_rows = sorted(
        (binding for binding in (bindings or []) if binding.get("member") == member),
        key=lambda binding: (binding.get("member") not in ["allUsers", "allAuthenticatedUsers"], str(binding.get("member") or "")),
    )

    data_dict: dict[str, Any] = {}
    for rtype in ("org", "folder", "project"):
        data_dict.setdefault(rtype, {})

    for row in member_rows:
        rtype, rname, pid = row["type"], row["name"], row["project_id"]
        data_dict.setdefault(rtype, {})
        roles = set(
            parse_string_list(
                row["roles"],
                allow_json=True,
                allow_python_literal=True,
                fallback_to_single=True,
            )
        )
        display = row.get("display_name", rname)
        pname = _project_name(pid)

        entry = data_dict[rtype].setdefault(
            rname,
            {
                "Direct Permissions": set(),
                "Inherited Permissions": [],
                "common_name": display if rtype in ["org", "project", "folder"] else rname,
                "parent_id": pid,
                "parent_name": pname,
            },
        )
        entry["Direct Permissions"].update(roles)

    for level in ("project", "folder", "org"):
        for asset, info in (data_dict.get(level) or {}).items():
            for anc_type, anc_name in session.find_ancestors(asset):
                anc_roles = data_dict.get(anc_type, {}).get(anc_name, {}).get("Direct Permissions")
                if anc_roles:
                    info["Inherited Permissions"].append({"ancestor": anc_name, "roles": anc_roles})

    for rtype, entries in data_dict.items():
        if rtype in ("project", "folder", "org"):
            continue
        for _name, info in entries.items():
            parent = info.get("parent_name")
            proj_data = data_dict.get("project", {}).get(parent)
            if proj_data:
                info["Inherited Permissions"] = list(proj_data["Inherited Permissions"] or [])
                info["Inherited Permissions"].append({"ancestor": parent, "roles": proj_data["Direct Permissions"]})
                continue
            for anc_type, anc_name in session.find_ancestors(parent):
                roles = data_dict.get(anc_type, {}).get(anc_name, {}).get("Direct Permissions")
                if roles:
                    info["Inherited Permissions"].append({"ancestor": anc_name, "roles": roles})

    if convenience_summary:
        add_convenience_roles(data_dict, convenience_summary)
    return data_dict
