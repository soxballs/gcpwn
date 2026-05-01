from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import sys
import time
from threading import Lock
from types import SimpleNamespace
from typing import List, Union, Optional, Tuple
import textwrap

# Typing libraries
from gcpwn.core.session import SessionUtility
from google.cloud.storage.client import Client
from google.cloud.storage.blob import Blob
from google.cloud.storage.bucket import Bucket
from google.cloud.storage.hmac_key import HMACKeyMetadata

from gcpwn.modules.iam.utilities.helpers import bucket_get_iam_policy,bucket_set_iam_policy

import json
import os
import requests
import re
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import extract_path_segment
from gcpwn.core.utils.service_runtime import get_cached_rows, parse_csv_file_args
from gcpwn.core.utils.persistence import save_to_table

from google.cloud import storage
from google.api_core.iam import Policy

from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from gcpwn.core.contracts import HashableResourceProxy


class HashableHMACKeyMetadata(HashableResourceProxy):
    def __init__(self, hmac_key, validated=True):
        self._hmac_key = hmac_key
        super().__init__(
            hmac_key,
            key_fields=("access_id",),
            validated=validated,
            repr_fields=("access_id", "service_account_email"),
        )


def _build_hmac_s3_client(access_id: str, secret_key: str):
    try:
        import boto3  # type: ignore
        from botocore.config import Config  # type: ignore
    except ImportError:
        print(
            f"{UtilityTools.RED}[X] HMAC XML API access requires `boto3`. "
            f"Install project dependencies or `pip install boto3`.{UtilityTools.RESET}"
        )
        return None

    return boto3.client(
        "s3",
        region_name="auto",
        endpoint_url="https://storage.googleapis.com",
        aws_access_key_id=access_id,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
     
class HashableCloudStorageBucket(HashableResourceProxy):
    def __init__(self, bucket, validated: bool = True):
        self._bucket = bucket
        super().__init__(bucket, key_fields=("name",), validated=validated, repr_fields=("name",))


class HashableCloudStorageBlob(HashableResourceProxy):
    def __init__(self, blob, validated: bool = True):
        self._blob = blob
        super().__init__(blob, key_fields=("name",), validated=validated, repr_fields=("name",))


class _CloudStorageBaseResource:
    def __init__(self, session):
        self.session = session

    @property
    def debug(self) -> bool:
        return getattr(self.session, "debug", False)

    def build_client(self, project_id: str):
        return storage.Client(credentials=self.session.credentials, project=project_id)


class CloudStorageHmacKeysResource(_CloudStorageBaseResource):
    TABLE_NAME = "cloudstorage_hmac_keys"
    COLUMNS = ["access_id", "state", "service_account_email", "secret"]
    LIST_PERMISSION = "storage.hmacKeys.list"
    GET_PERMISSION = "storage.hmacKeys.get"

    @staticmethod
    def list_with_client(storage_client: Client, debug: Optional[bool] = False) -> Union[List, None]:
        if debug:
            print("[DEUBG] Listing HMAC keys...")
        try:
            keys = list(storage_client.list_hmac_keys(show_deleted_keys=True))
        except NotFound as e:
            if "The requested project was not found" in str(e):
                print(f"{UtilityTools.RED}[X] 404: The project could not be used. It might be in a deleted state or not exist.{UtilityTools.RESET}")
            return None
        except Forbidden as e:
            if "does not have storage.hmacKeys.list" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have storage.hmacKeys.list permissions on bucket{UtilityTools.RESET}")
            return None
        except Exception as e:
            print("The storage.hmacKeys.list operation failed for unexpected reasons. See below:")
            print(str(e))
            return None
        if debug:
            print("[DEUBG] Successful completed list_hmac_keys...")
        return keys

    @staticmethod
    def get_with_client(storage_client: Client, access_id: str, debug: Optional[bool] = False) -> Union[HMACKeyMetadata, None]:
        if debug:
            print(f"[DEUBG] Getting HMAC key {access_id}...")
        try:
            key = storage_client.get_hmac_key_metadata(access_id)
        except Forbidden as e:
            if "does not have storage.hmacKeys.get" in str(e):
                print(f"{UtilityTools.RED}[X] The user does not have storage.hmacKeys.get permissions on bucket{UtilityTools.RESET}")
            return None
        except NotFound as e:
            if "Access ID not found in project" in str(e):
                print(f"{UtilityTools.RED}[X] The access ID does not appear to exist.{UtilityTools.RESET}")
            return None
        except Exception as e:
            print("The storage.hmacKeys.get operation failed for unexpected reasons. See below:")
            print(str(e))
            return None
        if debug:
            print("[DEUBG] Successful completed get_hmac_key...")
        return key

    @staticmethod
    def create_with_client(storage_client: Client, sa_email: str, debug: Optional[bool] = False) -> Union[Tuple[None, None], Tuple[str, HMACKeyMetadata]]:
        if debug:
            print(f"[DEUBG] Creating HMAC key for {sa_email}...")
        try:
            key, secret = storage_client.create_hmac_key(sa_email)
        except Forbidden as e:
            if "does not have storage.hmacKeys.create" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have storage.hmacKeys.create permissions on bucket{UtilityTools.RESET}")
            return (None, None)
        except Exception as e:
            print("The storage.hmacKeys.create operation failed for unexpected reasons. See below:")
            print(str(e))
            return (None, None)
        if debug:
            print("[DEUBG] Successful completed create_hmac_key...")
        return (key, secret)

    @staticmethod
    def update_with_client(storage_client: Client, access_id: str, state: str, debug: Optional[bool] = False) -> Union[int, None]:
        if debug:
            print(f"[DEUBG] Updating HMAC key for {access_id}...")
        try:
            hmac_object = storage_client.get_hmac_key_metadata(access_id)
            hmac_object.state = state
            hmac_object.update()
            if debug:
                print("[DEUBG] Successful completed update_hmac_key...")
            return 1
        except Forbidden as e:
            if "does not have storage.hmacKeys.update" in str(e) or "does not have storage.hmacKeys.create" in str(e):
                print(f"403: {UtilityTools.RED}[X] The user does not have storage.hmacKeys.update permissions on bucket{UtilityTools.RESET}")
        except Exception as e:
            print("The storage.hmacKeys.update operation failed for unexpected reasons. See below:")
            print(str(e))
        return None

    def list(self, *, project_id: str, action_dict=None):
        rows = self.list_with_client(self.build_client(project_id), debug=self.debug)
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        row = self.get_with_client(self.build_client(project_id), resource_id, debug=self.debug)
        if row:
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return row

    def save(self, rows):
        for row in rows or []:
            save_to_table(
                self.session,
                "cloudstorage_hmac_keys",
                row,
                extra_builder=lambda obj, raw: {
                    "project_id": raw.get("project_id") or raw.get("project") or getattr(obj, "project", ""),
                },
                dont_change=["secret"],
            )

    @staticmethod
    def save_key(key: HMACKeyMetadata, session: SessionUtility, secret: Optional[str] = None) -> None:
        if key and secret is not None:
            setattr(key, "secret", secret)
        CloudStorageHmacKeysResource(session).save([key] if key else [])

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False

    def list_saved_secrets(self):
        rows_returned = self.session.get_data(
            "cloudstorage_hmac_keys",
            columns=["access_id", "secret", "service_account_email"],
            conditions='secret != ""',
        )
        return rows_returned or None

    def resolve_service_account_email(self, *, project_id: str, access_id: str) -> str | None:
        normalized_access_id = str(access_id or "").strip().replace('"', '""')
        if not normalized_access_id:
            return None

        cached = self.session.get_data(
            "cloudstorage_hmac_keys",
            columns=["service_account_email"],
            conditions=f'access_id = "{normalized_access_id}"',
        ) or []
        for row in cached:
            email = str((row or {}).get("service_account_email") or "").strip()
            if email:
                return email

        row = self.get(project_id=project_id, resource_id=access_id)
        if row:
            self.save([row])
            return str(getattr(row, "service_account_email", "") or "").strip() or None
        return None

    def resolve_action_crednames(self, *, project_id: str, access_id: str) -> list[str]:
        email = self.resolve_service_account_email(project_id=project_id, access_id=access_id)
        if not email:
            normalized_access_id = str(access_id or "").strip()
            return [f"hmac:{normalized_access_id}"] if normalized_access_id else []

        escaped_email = email.replace('"', '""')
        rows = self.session.get_session_data("session", columns=["credname"], conditions=f'email = "{escaped_email}"') or []
        crednames = [str((row or {}).get("credname") or "").strip() for row in rows if str((row or {}).get("credname") or "").strip()]
        return crednames or [email]

    def enumerate(self, *, project_id: str, access_key_inputs: list[str], include_get: bool = False):
        all_hmacs = defaultdict(set)
        resource_actions = {
            "project_permissions": defaultdict(set),
            "folder_permissions": {},
            "organization_permissions": {},
        }

        if access_key_inputs:
            for key_path in access_key_inputs:
                target_project_id = extract_path_segment(key_path, "projects")
                access_id = extract_path_segment(key_path, "hmacKeys")
                if not target_project_id or not access_id:
                    continue
                hmac_obj = HMACKeyMetadata(
                    client=self.build_client(target_project_id),
                    access_id=access_id,
                    project_id=target_project_id,
                )
                all_hmacs[target_project_id].add(HashableHMACKeyMetadata(hmac_obj, validated=False))
        else:
            listed = self.list(project_id=project_id, action_dict=resource_actions)
            if listed not in ("Not Enabled", None):
                all_hmacs[project_id].update(HashableHMACKeyMetadata(item) for item in listed)
                self.save(listed)
            else:
                all_hmacs[project_id] = set()

        for hmac_project_id, hmac_objects in all_hmacs.items():
            for hmac_key in list(hmac_objects):
                if not include_get:
                    continue
                hmac_get = self.get(
                    project_id=hmac_project_id,
                    resource_id=hmac_key.access_id,
                    action_dict=resource_actions,
                )
                if hmac_get:
                    if access_key_inputs and not hmac_key.validated:
                        hmac_objects.discard(hmac_key)
                        hmac_objects.add(HashableHMACKeyMetadata(hmac_get))
                    self.save([hmac_get])

        return all_hmacs, resource_actions


class CloudStorageBucketsResource(_CloudStorageBaseResource):
    TABLE_NAME = "cloudstorage_buckets"
    COLUMNS = ["name", "location", "storage_class", "time_created"]
    LIST_PERMISSION = "storage.buckets.list"
    GET_PERMISSION = "storage.buckets.get"
    ACTION_RESOURCE_TYPE = "buckets"

    @staticmethod
    def check_existence(bucket_name: str, debug: Optional[bool] = False) -> bool:
        if debug:
            bucket_url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}"
            print(f"[DEBUG] Checking {bucket_url}")
        response = requests.head(f"https://www.googleapis.com/storage/v1/b/{bucket_name}")
        if response.status_code not in [400, 404]:
            print(f"[*] Bucket {bucket_name} appears to exist with status code {response.status_code}")
            return True
        if debug:
            print(f"[DEBUG] Bucket {bucket_name} returned {response.status_code}. Does not exist.")
        return False

    @staticmethod
    def test_bucket_permissions(
        client: Union[Client, None],
        bucket_name: str,
        gcpbucketbrute: Optional[bool] = False,
        authenticated: Optional[bool] = False,
        unauthenticated: Optional[bool] = False,
        debug: Optional[bool] = False,
    ) -> Tuple[List, List]:
        authenticated_permissions, unauthenticated_permissions = [], []

        if client and authenticated:
            try:
                authenticated_permissions = client.bucket(bucket_name).test_iam_permissions(
                    permissions=[
                        "storage.buckets.delete",
                        "storage.buckets.get",
                        "storage.buckets.getIamPolicy",
                        "storage.buckets.setIamPolicy",
                        "storage.buckets.update",
                        "storage.objects.create",
                        "storage.objects.delete",
                        "storage.objects.get",
                        "storage.objects.list",
                        "storage.objects.update",
                    ]
                )
            except NotFound:
                print(f"[-] 404  {bucket_name} does not appear to exist ")
                authenticated_permissions = []
            except Forbidden:
                print(f"[-] 403 Bucket Exists, but the user does not have storage.testIamPermissions permissions on bucket {bucket_name} ")
                authenticated_permissions = []
            except Exception as e:
                print(f"[-] 403 TestIAMPermissions failed for {bucket_name} for the following reason:\n{e}")
                authenticated_permissions = []

            if gcpbucketbrute and authenticated_permissions:
                print(f"\n    AUTHENTICATED ACCESS ALLOWED: {bucket_name}")
                if "storage.buckets.setIamPolicy" in authenticated_permissions:
                    print("        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)")
                if "storage.objects.list" in authenticated_permissions:
                    print("        - AUTHENTICATED LISTABLE (storage.objects.list)")
                if "storage.objects.get" in authenticated_permissions:
                    print("        - AUTHENTICATED READABLE (storage.objects.get)")
                if (
                    "storage.objects.create" in authenticated_permissions
                    or "storage.objects.delete" in authenticated_permissions
                    or "storage.objects.update" in authenticated_permissions
                ):
                    print("        - AUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)")
                print("        - ALL PERMISSIONS:")
                print(textwrap.indent(f"{json.dumps(authenticated_permissions, indent=4)}\n", "        "))
            elif gcpbucketbrute:
                print("\n    NO AUTHENTICATED ACCESS ALLOWED")

        if unauthenticated:
            unauth_url = (
                "https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions"
                "?permissions=storage.buckets.delete&permissions=storage.buckets.get"
                "&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy"
                "&permissions=storage.buckets.update&permissions=storage.objects.create"
                "&permissions=storage.objects.delete&permissions=storage.objects.get"
                "&permissions=storage.objects.list&permissions=storage.objects.update"
            ).format(bucket_name)
            unauthenticated_permissions_request = requests.get(unauth_url).json()
            if unauthenticated_permissions_request.get("permissions"):
                unauthenticated_permissions = unauthenticated_permissions_request["permissions"]
                if gcpbucketbrute:
                    print(f"\n    UNAUTHENTICATED ACCESS ALLOWED: {bucket_name}")
                    if "storage.buckets.setIamPolicy" in unauthenticated_permissions:
                        print("        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)")
                    if "storage.objects.list" in unauthenticated_permissions:
                        print("        - UNAUTHENTICATED LISTABLE (storage.objects.list)")
                    if "storage.objects.get" in unauthenticated_permissions:
                        print("        - UNAUTHENTICATED READABLE (storage.objects.get)")
                    if (
                        "storage.objects.create" in unauthenticated_permissions
                        or "storage.objects.delete" in unauthenticated_permissions
                        or "storage.objects.update" in unauthenticated_permissions
                    ):
                        print("        - UNAUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)")
                    print("        - ALL PERMISSIONS:")
                    print(textwrap.indent(f"{json.dumps(unauthenticated_permissions, indent=4)}\n", "            "))

            if gcpbucketbrute and not (authenticated_permissions or unauthenticated_permissions):
                print(f"    EXISTS: {bucket_name}")

        return authenticated_permissions, unauthenticated_permissions

    @staticmethod
    def list_with_client(storage_client: Client, debug: Optional[bool] = False) -> Union[List, None]:
        if debug:
            print("[DEUBG] Getting buckets...")
        try:
            bucket_list = list(storage_client.list_buckets())
        except NotFound as e:
            if "The requested project was not found" in str(e):
                print(f"{UtilityTools.RED}[X] The project could not be used. It might be in a deleted state or not exist.{UtilityTools.RESET}")
            return None
        except Forbidden as e:
            if "does not have storage.buckets.list" in str(e):
                print(f"{UtilityTools.RED}[X] The user does not have storage.buckets.list permissions on bucket{UtilityTools.RESET}")
            return None
        except Exception as e:
            print("The storage.buckets.list operation failed for unexpected reasons. See below:")
            print(str(e))
            return None
        if debug:
            print("[DEUBG] Successful completed list_buckets...")
        return bucket_list

    @staticmethod
    def get_with_client(storage_client: Client, bucket_name: str, debug: Optional[bool] = False) -> Union[Bucket, None]:
        if debug:
            print(f"[DEBUG] Getting bucket metadata for {bucket_name} ...")
        try:
            bucket_meta = storage_client.get_bucket(bucket_name)
        except NotFound:
            print(f"{UtilityTools.RED}[X] 404 Bucket {bucket_name} was not found{UtilityTools.RESET}")
            return None
        except Forbidden as e:
            if "does not have storage.buckets.get access" in str(e):
                print(f"{UtilityTools.RED}[X] 403 The user does not have storage.buckets.get permissions on bucket {bucket_name}{UtilityTools.RESET}")
            return None
        except Exception as e:
            print("An unknown exception occurred when trying to call get_bucket as follows:\n" + str(e))
            return None
        if debug:
            print("[DEBUG] Successfully completed get_bucket ...")
        return bucket_meta

    @staticmethod
    def list_with_hmac(storage_client, access_id, secret, project_id, debug=False):
        _ = (storage_client, project_id, debug)
        client = _build_hmac_s3_client(access_id, secret)
        if client is None:
            return None
        try:
            response = client.list_buckets()
            return [
                SimpleNamespace(
                    name=str(bucket.get("Name") or ""),
                    time_created=str(bucket.get("CreationDate") or ""),
                )
                for bucket in response.get("Buckets", [])
                if bucket.get("Name")
            ]
        except Exception as e:
            print("[X] Failed to list buckets via boto3 XML API client for following reason:")
            print(str(e))
            return None

    def manual_targets(self, *, project_id: str, bucket_names: str | None = None, bucket_file: str | None = None):
        client = self.build_client(project_id)
        return [client.bucket(name) for name in parse_csv_file_args(bucket_names, bucket_file)]

    def list(self, *, project_id: str, access_mode: str = "standard", access_id: str | None = None, hmac_secret: str | None = None, action_dict=None):
        client = self.build_client(project_id)
        if access_mode == "hmac":
            rows = self.list_with_hmac(client, access_id, hmac_secret, project_id, self.debug)
        else:
            rows = self.list_with_client(client, debug=self.debug)
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        row = self.get_with_client(self.build_client(project_id), resource_id, debug=self.debug)
        if row:
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return row

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        auth_perms, unauth_perms = self.test_bucket_permissions(
            self.build_client(project_id),
            resource_id,
            authenticated=True,
            unauthenticated=True,
            debug=self.debug,
        )
        if auth_perms:
            record_permissions(
                action_dict,
                permissions=auth_perms,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return auth_perms, unauth_perms

    @staticmethod
    def add_iam_member(
        storage_client: Client,
        bucket_name: Bucket,
        member: str,
        bucket_project_id: str,
        action_dict: dict,
        brute: Optional[bool] = False,
        role: Optional[str] = None,
        debug: Optional[bool] = False,
    ):
        policy, additional_bind = None, {"role": role, "members": [member]}

        if brute:
            print(f"[*] Overwiting {bucket_name} to just be {member}")
            policy = Policy()
            policy.bindings = [additional_bind]
            policy.version = 3
        else:
            print(f"[*] Fetching current policy for {bucket_name}...")
            policy = bucket_get_iam_policy(storage_client, bucket_name, debug=debug)

            if policy:
                if policy == 404:
                    print(f"{UtilityTools.RED}[X] Exiting the module as {bucket_name} does not exist. Double check the name. Note the gs:// prefix is not included{UtilityTools.RESET}")
                    return -1
                action_dict.setdefault(bucket_project_id, {}).setdefault("storage.buckets.getIamPolicy", {}).setdefault("buckets", set()).add(bucket_name)
                policy.bindings.append(additional_bind)
            else:
                print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --brute to OVERWRITE entire bucket IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
                return -1

        if policy is None:
            print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
            return -1

        print(f"[*] New policy below being added to {bucket_name} \n{policy.bindings}")
        status = bucket_set_iam_policy(storage_client, bucket_name, policy, debug=debug)

        if status:
            if status == 404:
                print(f"{UtilityTools.RED}[X] Exiting the module as {bucket_name} does not exist. Double check the name. Note the gs:// prefix is not included{UtilityTools.RESET}")
                return -1
            action_dict.setdefault(bucket_project_id, {}).setdefault("storage.buckets.setIamPolicy", {}).setdefault("buckets", set()).add(bucket_name)

        return status

    def save(self, rows, *, xml_mode: bool = False):
        for row in rows or []:
            if xml_mode:
                save_to_table(
                    self.session,
                    "cloudstorage_buckets",
                    row,
                    defaults={"project_id": self.session.project_id},
                    only_if_new_columns=["name"],
                )
            else:
                save_to_table(self.session, "cloudstorage_buckets", row, defaults={"project_id": self.session.project_id})

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False

    def enumerate(
        self,
        *,
        project_id: str,
        include_get: bool = False,
        include_iam: bool = False,
        access_id: str | None = None,
        hmac_secret: str | None = None,
        bucket_names: str | None = None,
        bucket_file: str | None = None,
        access_mode: str = "standard",
    ):
        storage_actions = {
            "project_permissions": defaultdict(set),
            "folder_permissions": {},
            "organization_permissions": {},
        }
        bucket_api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        bucket_iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        bucket_targets = list(
            self.manual_targets(
                project_id=project_id,
                bucket_names=bucket_names,
                bucket_file=bucket_file,
            )
        )
        manual_buckets_requested = bool(bucket_targets)
        validated_buckets = {}

        if not bucket_targets:
            listed = self.list(
                project_id=project_id,
                access_mode=access_mode,
                access_id=access_id,
                hmac_secret=hmac_secret,
                action_dict=storage_actions if access_mode == "standard" else None,
            )
            if listed not in ("Not Enabled", None):
                bucket_targets = list(listed)
                self.save(bucket_targets, xml_mode=(access_mode == "hmac"))

        for bucket in list(bucket_targets):
            working_bucket = bucket
            bucket_has_detail = False
            print(f"[**] Reviewing {working_bucket.name}")
            if include_get and access_mode == "standard":
                bucket_get = self.get(
                    project_id=project_id,
                    resource_id=working_bucket.name,
                    action_dict=bucket_api_actions,
                )
                if bucket_get:
                    working_bucket = bucket_get
                    bucket_has_detail = True
                    self.save([working_bucket])

            if include_iam:
                auth_perms, unauth_perms = self.get_iam_permissions(
                    project_id=project_id,
                    resource_id=working_bucket.name,
                    action_dict=bucket_iam_actions,
                )
                if unauth_perms:
                    self.session.add_unauthenticated_permissions(
                        {"name": working_bucket.name, "type": "bucket", "permissions": str(unauth_perms)},
                        project_id=project_id,
                    )

            if manual_buckets_requested and not bucket_has_detail:
                continue
            validated_buckets[working_bucket] = []

        return {
            "validated_buckets": validated_buckets,
            "bucket_targets": list(bucket_targets),
            "manual_requested": manual_buckets_requested,
            "scope_actions": storage_actions,
            "api_actions": bucket_api_actions,
            "iam_actions": bucket_iam_actions,
        }


class CloudStorageBlobsResource(_CloudStorageBaseResource):
    TABLE_NAME = "cloudstorage_bucketblobs"
    COLUMNS = ["bucket_name", "name", "size", "updated"]
    LIST_PERMISSION = "storage.objects.list"
    GET_PERMISSION = "storage.objects.get"

    @staticmethod
    def _bucket_name(bucket) -> str:
        return str(getattr(bucket, "name", "") or "").strip() or str(bucket)

    @staticmethod
    def upload_with_client(
        storage_client: Client,
        bucket_name: str,
        remote_path: str,
        local_blob_path: Optional[str] = None,
        data_string: Optional[str] = None,
        debug: Optional[bool] = False,
    ) -> Union[None, bool]:
        if debug:
            if local_blob_path:
                print(f"[DEBUG] Proceeding to upload {local_blob_path} to {bucket_name}/{remote_path} ...")
            elif data_string:
                print(f"[DEBUG] Proceeding to upload {data_string} to {bucket_name}/{remote_path} ...")

        try:
            uploading_bucket = storage_client.bucket(bucket_name)
            uploading_blob = uploading_bucket.blob(remote_path)
            if local_blob_path:
                uploading_blob.upload_from_filename(local_blob_path)
            elif data_string is not None:
                uploading_blob.upload_from_string(data_string)
        except FileNotFoundError as e:
            if f"No such file or directory: '{local_blob_path}'" in str(e):
                print(f"{UtilityTools.RED}[X] File {local_blob_path} does not exist. Exiting...{UtilityTools.RESET}")
            return None
        except Forbidden as e:
            if "does not have storage.objects.create access to the Google Cloud Storage object" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have storage.objects.create permissions on the target bucket{UtilityTools.RESET}")
            return None
        except Exception as e:
            print("[X] The storage.objects.create API call failed for uknown reasons. See the error below:")
            print(str(e))
            return None

        if debug:
            print("[DEBUG] Completed upload_with_client")
        return True

    @staticmethod
    def upload_with_hmac(
        bucket_name,
        local_blob_path,
        remote_blob_path,
        access_id,
        secret_key,
        data_string: Optional[str] = None,
        debug: Optional[bool] = None,
    ):
        client = _build_hmac_s3_client(access_id, secret_key)
        if client is None:
            return None

        try:
            if debug:
                print(f"[DEBUG] Uploading HMAC object to {bucket_name}/{remote_blob_path}")
            if data_string is not None:
                client.put_object(Bucket=bucket_name, Key=remote_blob_path, Body=data_string.encode("utf-8"))
            elif local_blob_path:
                with open(local_blob_path, "rb") as input_file:
                    client.put_object(Bucket=bucket_name, Key=remote_blob_path, Body=input_file)
            else:
                print(f"{UtilityTools.RED}[X] No upload data was provided for HMAC upload.{UtilityTools.RESET}")
                return None
            return True
        except FileNotFoundError:
            print(f"{UtilityTools.RED}[X] File {local_blob_path} does not exist. Exiting...{UtilityTools.RESET}")
        except Exception as e:
            print("[X] Failed to upload blob via XML API for following reason:")
            print(str(e))
        return None

    @staticmethod
    def list_with_client(storage_client: Client, bucket_name: str, debug: Optional[bool] = False) -> Union[List, None]:
        if debug:
            print(f"[DEBUG] Listing blobs for {bucket_name}")
        try:
            blob_list = list(storage_client.list_blobs(bucket_name))
        except NotFound as e:
            if "does not exist" in str(e):
                print(f"{UtilityTools.RED}[X] 404: Bucket {bucket_name} does not appear to exist when calling list objects{UtilityTools.RESET}")
            return None
        except Forbidden as e:
            if "does not have storage.objects.list" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have storage.objects.list permissions on bucket {bucket_name}{UtilityTools.RESET}")
            return None
        except Exception as e:
            print(f"The storage.objects.list operation failed for unexpected reasons for bucket {bucket_name}. See below:")
            print(str(e))
            return None
        if debug:
            print("[DEUBG] Successful completed list_blobs...")
        return blob_list

    @staticmethod
    def get_with_bucket(bucket: Bucket, blob_name: str, debug: Optional[bool] = False) -> Union[Blob, None]:
        if debug:
            print(f"[DEBUG] Getting blob meta {blob_name} for {bucket.name}")
        try:
            blob_meta = bucket.get_blob(blob_name)
        except Forbidden as e:
            if "does not have storage.objects.get access" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have storage.objects.get permissions on blob {blob_name} for bucket {bucket.name}{UtilityTools.RESET}")
            return None
        except Exception as e:
            print(str(e))
            print("[DEBUG] UNKNOWN EXCEPTION WHEN GETTING BLOB DETAILS")
            return None
        if debug:
            print("[DEUBG] Successful completed get_blob...")
        return blob_meta

    @staticmethod
    def list_with_hmac(storage_client, access_id, secret, bucket_name, project_id, debug=False):
        _ = (storage_client, project_id, debug)
        client = _build_hmac_s3_client(access_id, secret)
        if client is None:
            return None
        try:
            response = client.list_objects(Bucket=bucket_name)
            return [
                SimpleNamespace(
                    name=str(blob.get("Key") or ""),
                    size=blob.get("Size"),
                    updated=str(blob.get("LastModified") or ""),
                    generation=str(blob.get("Generation") or ""),
                    metageneration=str(blob.get("MetaGeneration") or ""),
                    etag=str(blob.get("ETag") or ""),
                    bucket_name=bucket_name,
                )
                for blob in response.get("Contents", [])
                if blob.get("Key")
            ]
        except Exception as e:
            print("[X] Failed to list blobs via boto3 XML API client for following reason:")
            print(str(e))
            return None

    @staticmethod
    def download_with_client(
        storage_client,
        bucket,
        blob,
        project_id,
        debug=False,
        output_folder=None,
        user_regex_pattern=None,
        blob_size_limit=None,
    ):
        _ = storage_client
        bucket_name = bucket.name
        blob_name = blob.name
        blob_size = blob.size
        if (user_regex_pattern is None or re.search(user_regex_pattern, blob_name)) and (
            blob_size_limit is None or blob_size <= blob_size_limit
        ):
            if debug:
                print(f"[DEBUG] Downloading blob {blob_name}...")
            first_directory = output_folder + "/REST"
            directory_to_store = f"{first_directory}/{project_id or 'Unknown'}/{bucket_name}/"
            os.makedirs(directory_to_store, exist_ok=True)
            if "/" in blob_name:
                parent_prefix = blob_name.rpartition("/")[0]
                final_folder = f"{directory_to_store}{parent_prefix}" if parent_prefix else directory_to_store
                if not os.path.exists(final_folder):
                    os.makedirs(final_folder, exist_ok=True)
            destination_filename = directory_to_store + blob_name
            if destination_filename[-1] != "/":
                try:
                    blob.download_to_filename(destination_filename)
                except Forbidden as e:
                    if "storage.objects.get" in str(e):
                        print(f"[-] The user could not download {blob_name}")
                    return None
                except Exception as e:
                    if project_id:
                        print(f"The storage.objects.get operation failed for unexpected reasons for {project_id}:{bucket_name}. See below:")
                    else:
                        print(f"The storage.objects.get operation failed for unexpected reasons for {bucket_name}. See below:")
                    print(str(e))
                    return None
        return 1

    @staticmethod
    def download_with_hmac(storage_client, access_id, secret_key, bucket_name, blob_name, project_id, debug=False, output_folder=None):
        _ = (storage_client, debug)
        client = _build_hmac_s3_client(access_id, secret_key)
        if client is None:
            return None
        if project_id is None:
            project_id = ""
        try:
            first_directory = output_folder + "/XML"
            directory_to_store = f"{first_directory}/{project_id}/{bucket_name}/"
            os.makedirs(directory_to_store, exist_ok=True)
            if "/" in blob_name:
                parent_prefix = blob_name.rpartition("/")[0]
                final_folder = f"{directory_to_store}{parent_prefix}" if parent_prefix else directory_to_store
                if not os.path.exists(final_folder):
                    os.makedirs(final_folder, exist_ok=True)
            destination_filename = directory_to_store + blob_name
            if destination_filename[-1] != "/":
                response = client.get_object(Bucket=bucket_name, Key=blob_name)
                with open(destination_filename, "wb") as output_file:
                    output_file.write(response["Body"].read())
        except Exception as e:
            print("[X] Failed to download blob via boto3 XML API client for following reason:")
            print(str(e))
            return None
        return 1

    def resolve_cached_buckets(self, *, project_id: str):
        client = self.build_client(project_id)
        rows = get_cached_rows(self.session, "cloudstorage_buckets", project_id=project_id, columns=["name"])
        return [client.bucket(row["name"]) for row in rows if row.get("name")]

    def list(self, *, project_id: str, bucket, access_mode: str = "standard", access_id: str | None = None, hmac_secret: str | None = None, action_dict=None):
        client = self.build_client(project_id)
        if access_mode == "hmac":
            rows = self.list_with_hmac(client, access_id, hmac_secret, bucket.name, project_id, self.debug)
        else:
            rows = self.list_with_client(client, bucket.name, debug=self.debug)
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=project_id,
                resource_type="buckets",
                resource_label=bucket.name,
            )
        return rows

    def get(self, *, bucket, resource_id: str):
        return self.get_with_bucket(bucket, resource_id, debug=self.debug)

    def save(self, rows, *, xml_mode: bool = False):
        for row in rows or []:
            if xml_mode:
                save_to_table(
                    self.session,
                    "cloudstorage_bucketblobs",
                    row,
                    defaults={"project_id": self.session.project_id},
                    only_if_new_columns=["project_id", "name"],
                )
            else:
                save_to_table(
                    self.session,
                    "cloudstorage_bucketblobs",
                    row,
                    defaults={"project_id": self.session.project_id},
                    extra_builder=lambda obj, _raw: {
                        "bucket_name": getattr(getattr(obj, "bucket", None), "name", "") or getattr(obj, "bucket_name", ""),
                    },
                )

    def download(
        self,
        *,
        project_id: str,
        bucket,
        blob,
        output_folder: str | None = None,
        user_regex_pattern: str | None = None,
        blob_size_limit: int | None = None,
        access_id: str | None = None,
        hmac_secret: str | None = None,
        access_mode: str = "standard",
        action_dict=None,
    ) -> bool:
        client = self.build_client(project_id)
        if access_mode == "hmac":
            status = self.download_with_hmac(
                client,
                access_id,
                hmac_secret,
                bucket.name,
                blob.name,
                project_id,
                debug=getattr(self.session, "debug", False),
                output_folder=output_folder,
            )
        else:
            status = self.download_with_client(
                client,
                bucket,
                blob,
                project_id,
                debug=self.debug,
                output_folder=output_folder,
                user_regex_pattern=user_regex_pattern,
                blob_size_limit=blob_size_limit,
            )
        if status:
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type="buckets",
                resource_label=bucket.name,
            )
        return status

    def _process_blob_download(
        self,
        *,
        project_id: str,
        bucket,
        blob,
        output_dir: str,
        user_regex_pattern: str | None,
        blob_size_limit: int | None,
        access_id: str | None,
        hmac_secret: str | None,
        access_mode: str,
        action_dict,
        lock: Lock,
        counter: dict[str, int],
        total: int,
    ) -> bool:
        bucket_name = self._bucket_name(bucket)
        self.download(
            project_id=project_id,
            bucket=bucket,
            blob=blob,
            output_folder=output_dir,
            user_regex_pattern=user_regex_pattern,
            blob_size_limit=blob_size_limit,
            access_id=access_id,
            hmac_secret=hmac_secret,
            access_mode=access_mode,
            action_dict=action_dict,
        )
        with lock:
            counter["count"] += 1
            print(
                f"\r[***] Bucket {bucket_name}: Processed {counter['count']} of {total} blobs...",
                end="",
            )
            sys.stdout.flush()
        return True

    def enumerate(
        self,
        *,
        project_id: str,
        bucket_targets: list,
        blob_name_inputs: list[str],
        download: bool = False,
        output: str | None = None,
        good_regex: str | None = None,
        file_size: int | None = None,
        time_limit: str | None = None,
        threads: int = 1,
        access_id: str | None = None,
        hmac_secret: str | None = None,
        access_mode: str = "standard",
    ):
        blob_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        bucket_blob_map = {}

        for bucket in bucket_targets:
            bucket_name = self._bucket_name(bucket)
            print(f"[*] Enumerating blobs in bucket {bucket_name}...")
            blob_list = self.list(
                project_id=project_id,
                bucket=bucket,
                access_mode=access_mode,
                access_id=access_id,
                hmac_secret=hmac_secret,
                action_dict=blob_actions,
            )
            if blob_list in ("Not Enabled", None):
                continue
            bucket_blob_map[bucket] = []

            if blob_name_inputs:
                allowed_blob_names = set(blob_name_inputs)
                blob_list = [blob for blob in blob_list if blob.name in allowed_blob_names]

            self.save(blob_list, xml_mode=(access_mode == "hmac"))
            bucket_blob_map[bucket] = [
                blob.name for blob in blob_list if getattr(blob, "name", None) and not blob.name.endswith("/")
            ]

            if not download:
                continue

            output_dir = str(
                self.session.resolve_output_path(
                    requested_path=output,
                    service_name="storage",
                    project_id=project_id,
                    target="download",
                )
            )
            non_folder_blobs = [
                blob for blob in blob_list if getattr(blob, "name", None) and not blob.name.endswith("/")
            ]
            if not non_folder_blobs:
                print(f"[*] Bucket {bucket_name}: no downloadable blobs found.")
                continue
            print(f"[*] Bucket {bucket_name}: downloading {len(non_folder_blobs)} blob(s)...")
            start_time = time.time()
            lock = Lock()
            counter = {"count": 0}

            try:
                if threads == 1:
                    for blob in non_folder_blobs:
                        if time_limit and (time.time() - start_time) > int(time_limit):
                            print(f"\n[-] Time limit of {time_limit} reached for bucket {bucket.name}")
                            break
                        self._process_blob_download(
                            project_id=project_id,
                            bucket=bucket,
                            blob=blob,
                            output_dir=output_dir,
                            user_regex_pattern=good_regex,
                            blob_size_limit=file_size,
                            access_id=access_id,
                            hmac_secret=hmac_secret,
                            access_mode=access_mode,
                            action_dict=blob_actions,
                            lock=lock,
                            counter=counter,
                            total=len(non_folder_blobs),
                        )
                else:
                    with ThreadPoolExecutor(max_workers=threads) as executor:
                        list(
                            executor.map(
                                lambda blob: self._process_blob_download(
                                    project_id=project_id,
                                    bucket=bucket,
                                    blob=blob,
                                    output_dir=output_dir,
                                    user_regex_pattern=good_regex,
                                    blob_size_limit=file_size,
                                    access_id=access_id,
                                    hmac_secret=hmac_secret,
                                    access_mode=access_mode,
                                    action_dict=blob_actions,
                                    lock=lock,
                                    counter=counter,
                                    total=len(non_folder_blobs),
                                ),
                                non_folder_blobs,
                            )
                        )
                if non_folder_blobs:
                    print()
            except KeyboardInterrupt:
                print(f"\n[*] Interrupted blob processing for bucket {bucket_name}. Moving to the next bucket...")

        return bucket_blob_map, blob_actions
