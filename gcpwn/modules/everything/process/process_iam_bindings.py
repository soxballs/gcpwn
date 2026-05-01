import argparse
import traceback

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.iam_simplifier import create_simplified_hierarchy_permissions
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.everything.utilities.iam_policy_bindings import IAMPolicyBindingsResource
from gcpwn.modules.everything.utilities.helpers import (
    build_roles_and_assets_for_member,
    canonical_iam_member,
    consolidate_convenience_roles,
    generate_summary_of_roles_or_vulns,
    split_members_by_kind,
)

def run_module(user_args, session):
    parser = argparse.ArgumentParser(description="Consolidate all IAM Bindings into 1 Member Rows", allow_abbrev=False)
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Get verbose data returned")
    parser.add_argument("--txt", action="store_true", help="Output in TXT format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--silent", action="store_true", help="No stdout")
    parser.add_argument("--output", required=False, help="Output directory to store IAM snapshot report")
    parser.add_argument("--force-refresh-bindings", action="store_true", help="Re-enumerate IAM bindings before processing (recommended if new resources were added)")
    args = parser.parse_args(user_args)

    debug = args.debug

    def _load_bindings():
        simplified = create_simplified_hierarchy_permissions(
            session.get_data(
                "iam_allow_policies",
                columns=["project_id", "resource_type", "resource_name", "policy"],
            )
            or [],
            include_inheritance=False,
            normalize_member=canonical_iam_member,
            is_convenience_member=lambda member: str(member or "").strip().startswith(
                ("projectViewer:", "projectEditor:", "projectOwner:")
            ),
        )
        return list(simplified.get("flattened_member_rows") or [])

    bindings = _load_bindings()
    if args.force_refresh_bindings or not bindings:
        if args.force_refresh_bindings:
            print("[*] Refreshing IAM bindings (forced)...")
        else:
            print("[*] No IAM bindings found; enumerating IAM policies across resources now...")
        try:
            IAMPolicyBindingsResource(session).run(save_raw_policies=True)
        except Exception:
            if debug:
                print(traceback.format_exc())
        bindings = _load_bindings()
    if not bindings:
        print("[X] No IAM bindings were found. Run 'modules run enum_iam --policy-bindings' first.")
        return

    members = {str(b["member"] or "").strip() for b in bindings if str(b["member"] or "").strip()}
    conv_members, valid_members = split_members_by_kind(members)

    conv_summary = consolidate_convenience_roles(session, conv_members, bindings)

    if valid_members and debug:
        print("[*] Proceeding with the following valid members:\n  - " + "\n  - ".join(valid_members))
        print(f"[**] Processing IAM roles for {valid_members[0]}. Depending on size of org/resources this might take awhile...")

    for index, member in enumerate(valid_members):
        data_dict = build_roles_and_assets_for_member(
            session,
            member=member,
            bindings=bindings,
            convenience_summary=conv_summary,
        )

        if not data_dict:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Processing failed. Exiting...{UtilityTools.RESET}")
            return -1

        crednames = None
        if member not in ["allUsers", "allAuthenticatedUsers"]:
            
            print(f"[*] Checking if {member} is tied to any existing crednames")

            email = member.split(":")[1]
            crednames = session.get_session_data("session", columns=["credname"], conditions=f"email = \"{email}\"")

            if crednames and debug:
                crednames = [item['credname'] for item in crednames]
                print(f"[*] The following crednames are tied to {email}:")
                for credname in crednames:
                    print(f"  - {credname}")

        row = {"member": member, "roles_and_assets": data_dict}
        if crednames:
            row["crednames"] = crednames
        save_to_table(session, "member_permissions_summary", row)

        generate_summary_of_roles_or_vulns(
            session,
            member,
            data_dict,
            first_run=(index == 0),
            output_file=args.output,
            csv=args.csv,
            txt=args.txt,
            stdout=not args.silent
        )
