from __future__ import annotations


from google.cloud import redis_v1



from google.api_core.exceptions import (
    NotFound,
    Forbidden
)

from gcpwn.core.console import UtilityTools
from gcpwn.core.contracts import HashableResourceProxy
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import extract_project_id_from_resource
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.service_runtime import is_api_disabled_error


def list_redis_instances(redis_client, parent, debug=False):
    
    if debug:
        print(f"[DEBUG] Listing Redis instances for: {parent}...")
    
    project_id = extract_project_id_from_resource(parent)

    redis_instance_list = []

    try:

        request = redis_v1.ListInstancesRequest(
            parent=parent,
        )

        redis_instance_list = list(redis_client.list_instances(request=request))
        
    except Forbidden as e:

        if "does not have redis.instances.list" in str(e):
            UtilityTools.print_403_api_denied("redis.instances.list", project_id = project_id)

        elif is_api_disabled_error(e):
            UtilityTools.print_403_api_disabled("Memorystore Redis", project_id)
            return "Not Enabled"
        print(str(e))
        return None

    except NotFound as e:

        if "was not found" in str(e):
            UtilityTools.print_404_resource(project_id)
        return None

    except Exception as e:
        project_id = extract_project_id_from_resource(parent)
        UtilityTools.print_500(project_id, "redis.instances.list", e)
        return None

    return redis_instance_list

def get_redis_instance(redis_instances_client, name, debug=False):

    if debug:
        print(f"[DEBUG] Getting {name}...")

    project_id = extract_project_id_from_resource(name)

    redis_instance_metdata = None

    try:

        # Initialize request argument(s)
        request = redis_v1.GetInstanceRequest(
            name=name,
        )

        # Make the request
        redis_instance_metdata = redis_instances_client.get_instance(request=request)

    except Forbidden as e:
        
        if "does not have redis.instances.get" in str(e):
            UtilityTools.print_403_api_denied("redis.instances.get", resource_name=name)

        elif is_api_disabled_error(e):
            UtilityTools.print_403_api_disabled("Memorystore Redis", project_id)

    except NotFound as e:

        if "was not found" in str(e):
            UtilityTools.print_404_resource(name)

    except Exception as e:

        UtilityTools.print_500(name, "redis.instances.get", e)

    if debug:
        print("[DEBUG] Succcessfully completed get_redis_instance ...")

    # Handle the response
    return redis_instance_metdata  

def get_redis_instance_auth_string(redis_instances_client, name, debug=False):

    if debug:
        print(f"[DEBUG] Getting auth string for {name}...")

    project_id = extract_project_id_from_resource(name)

    redis_instance_metdata = None

    try:

        # Initialize request argument(s)
        request = redis_v1.GetInstanceAuthStringRequest(
            name=name,
        )

        # Make the request
        redis_instance_metdata = redis_instances_client.get_instance_auth_string(request=request)

    except Forbidden as e:
        
        if "does not have redis.instances.getAuthString" in str(e):
            UtilityTools.print_403_api_denied("redis.instances.getAuthString", resource_name=name)

        elif is_api_disabled_error(e):
            UtilityTools.print_403_api_disabled("Memorystore Redis", project_id)

    except NotFound as e:

        if "was not found" in str(e):
            UtilityTools.print_404_resource(name)

    except Exception as e:

        UtilityTools.print_500(name, "redis.instances.getAuthString", e)

    if debug:
        print("[DEBUG] Succcessfully completed get_redis_instance_auth_string ...")

    # Handle the response
    return redis_instance_metdata  


class HashableRedisInstance(HashableResourceProxy):
    auth_string = None
    state_output = None

    def __init__(self, redis_instance, validated: bool = True):
        self._redis_instance = redis_instance
        super().__init__(
            redis_instance,
            key_fields=("name",),
            validated=validated,
            repr_fields=("name",),
        )
        self.state_output = {
            0: "STATE_UNSPECIFIED",
            1: "CREATING",
            2: "READY",
            3: "UPDATING",
            4: "DELETING",
            5: "REPAIRING",
            6: "MAINTENANCE",
            7: "IMPORTING",
            8: "FAILING_OVER",
        }.get(getattr(redis_instance, "state", None))


class MemorystoreRedisResource:
    TABLE_NAME = "memorystore-redis"
    COLUMNS = ["name", "display_name", "state_output", "location_id", "host", "port", "auth_enabled", "auth_string"]
    LIST_PERMISSION = "redis.instances.list"
    GET_PERMISSION = "redis.instances.get"
    GET_AUTH_STRING_PERMISSION = "redis.instances.getAuthString"

    def __init__(self, session):
        self.session = session
        self.client = redis_v1.CloudRedisClient(credentials=session.credentials)

    def list(self, *, parent: str, action_dict=None):
        rows = list_redis_instances(self.client, parent, debug=getattr(self.session, "debug", False))
        project_id = extract_project_id_from_resource(parent)
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def get(self, *, resource_id: str, action_dict=None):
        row = get_redis_instance(self.client, resource_id, debug=getattr(self.session, "debug", False))
        project_id = extract_project_id_from_resource(resource_id)
        if row:
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return row

    def get_auth_string(self, *, resource_id: str, action_dict=None):
        auth_string = get_redis_instance_auth_string(self.client, resource_id, debug=getattr(self.session, "debug", False))
        project_id = extract_project_id_from_resource(resource_id)
        if auth_string:
            record_permissions(
                action_dict,
                permissions=self.GET_AUTH_STRING_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return auth_string

    def save(self, rows):
        for row in rows or []:
            save_to_table(
                self.session,
                "memorystore-redis",
                row,
                extra_builder=lambda _obj, raw: {
                    "project_id": extract_project_id_from_resource(raw.get("name", "")),
                },
            )

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False
