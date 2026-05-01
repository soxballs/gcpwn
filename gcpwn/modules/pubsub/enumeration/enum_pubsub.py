from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import parse_component_args, parse_csv_file_args, resolve_selected_components
from gcpwn.modules.pubsub.utilities.helpers import PubSubSchemasResource, PubSubSnapshotsResource, PubSubSubscriptionsResource, PubSubTopicsResource


COMPONENTS = [
    ("topics", "Enumerate Pub/Sub topics"),
    ("subscriptions", "Enumerate Pub/Sub subscriptions"),
    ("schemas", "Enumerate Pub/Sub schemas"),
    ("snapshots", "Enumerate Pub/Sub snapshots"),
]


def _hydrate_pubsub_rows(rows, getter):
    return [row for row in hydrate_get_request_rows(rows, lambda raw_row, payload: getter(raw_row, payload)) if row]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--topic-names",
            type=str,
            help="Topic names in comma-separated format using `projects/PROJECT_ID/topics/TOPIC_ID`.",
        )
        parser.add_argument(
            "--topic-names-file",
            type=str,
            help="File containing topic names, one per line or comma-separated, using the same formats as --topic-names.",
        )
        parser.add_argument(
            "--subscription-names",
            type=str,
            help="Subscription names in comma-separated format using `projects/PROJECT_ID/subscriptions/SUBSCRIPTION_ID`.",
        )
        parser.add_argument(
            "--subscription-names-file",
            type=str,
            help="File containing subscription names, one per line or comma-separated, using the same formats as --subscription-names.",
        )
        parser.add_argument(
            "--schema-names",
            type=str,
            help="Schema names in comma-separated format using `projects/PROJECT_ID/schemas/SCHEMA_ID`.",
        )
        parser.add_argument(
            "--schema-names-file",
            type=str,
            help="File containing schema names, one per line or comma-separated, using the same formats as --schema-names.",
        )
        parser.add_argument(
            "--snapshot-names",
            type=str,
            help="Snapshot names in comma-separated format using `projects/PROJECT_ID/snapshots/SNAPSHOT_ID`.",
        )
        parser.add_argument(
            "--snapshot-names-file",
            type=str,
            help="File containing snapshot names, one per line or comma-separated, using the same formats as --snapshot-names.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Pub/Sub resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Pub/Sub topics, subscriptions, schemas, and snapshots"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    topic_names = parse_csv_file_args(getattr(args, "topic_names", None), getattr(args, "topic_names_file", None))
    subscription_names = parse_csv_file_args(
        getattr(args, "subscription_names", None),
        getattr(args, "subscription_names_file", None),
    )
    schema_names = parse_csv_file_args(getattr(args, "schema_names", None), getattr(args, "schema_names_file", None))
    snapshot_names = parse_csv_file_args(
        getattr(args, "snapshot_names", None),
        getattr(args, "snapshot_names_file", None),
    )

    if topic_names:
        args.topics = True
    if subscription_names:
        args.subscriptions = True
    if schema_names:
        args.schemas = True
    if snapshot_names:
        args.snapshots = True
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id
    topic_resource = PubSubTopicsResource(session)
    subscription_resource = PubSubSubscriptionsResource(session)
    schemas_resource = PubSubSchemasResource(session)
    snapshots_resource = PubSubSnapshotsResource(session)
    scope_actions = {"project_permissions": defaultdict(set), "folder_permissions": {}, "organization_permissions": {}}
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    if selected.get("topics", False):
        manual_topics_requested = bool(topic_names)
        topics = []

        if manual_topics_requested and args.get:
            topics = _hydrate_pubsub_rows(
                topic_names,
                lambda row, _payload: topic_resource.get(resource_id=str(row).strip(), action_dict=api_actions),
            )
        elif not manual_topics_requested:
            topics = topic_resource.list(project_id=project_id, action_dict=scope_actions) or []

            if args.get and topics:
                topics = _hydrate_pubsub_rows(
                    topics,
                    lambda _row, payload: topic_resource.get(
                        resource_id=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )

        if topics:
            topic_resource.save(topics)
        if args.iam:
            topic_targets = topic_names if manual_topics_requested else [
                str(topic.get("name") if isinstance(topic, dict) else getattr(topic, "name", "")).strip()
                for topic in topics
                if str(topic.get("name") if isinstance(topic, dict) else getattr(topic, "name", "")).strip()
            ]
            for name in topic_targets:
                topic_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

        show_topic_summary = bool(topics) or not manual_topics_requested
        if show_topic_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Pub/Sub Topics",
                topics,
                ["name", "kms_key_name", "labels"],
                primary_resource="Topics",
                primary_sort_key="name",
                )
        elif args.get:
            print("[*] No Pub/Sub topics found for the supplied --topic-names.")
        else:
            print("[*] Manual --topic-names supplied without --get; skipping topic summary.")

    if selected.get("subscriptions", False):
        manual_subscriptions_requested = bool(subscription_names)
        subscriptions = []

        if manual_subscriptions_requested and args.get:
            subscriptions = _hydrate_pubsub_rows(
                subscription_names,
                lambda row, _payload: subscription_resource.get(resource_id=str(row).strip(), action_dict=api_actions),
            )
        elif not manual_subscriptions_requested:
            subscriptions = subscription_resource.list(project_id=project_id, action_dict=scope_actions) or []

            if args.get and subscriptions:
                subscriptions = _hydrate_pubsub_rows(
                    subscriptions,
                    lambda _row, payload: subscription_resource.get(
                        resource_id=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )

        if subscriptions:
            subscription_resource.save(subscriptions)
        if args.iam:
            subscription_targets = subscription_names if manual_subscriptions_requested else [
                str(subscription.get("name") if isinstance(subscription, dict) else getattr(subscription, "name", "")).strip()
                for subscription in subscriptions
                if str(subscription.get("name") if isinstance(subscription, dict) else getattr(subscription, "name", "")).strip()
            ]
            for name in subscription_targets:
                subscription_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

        show_subscription_summary = bool(subscriptions) or not manual_subscriptions_requested
        if show_subscription_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Pub/Sub Subscriptions",
                subscriptions,
                ["name", "topic", "filter", "state"],
                primary_resource="Subscriptions",
                primary_sort_key="name",
                )
        elif args.get:
            print("[*] No Pub/Sub subscriptions found for the supplied --subscription-names.")
        else:
            print("[*] Manual --subscription-names supplied without --get; skipping subscription summary.")

    if selected.get("schemas", False):
        manual_schemas_requested = bool(schema_names)
        schemas = []

        if manual_schemas_requested and args.get:
            schemas = _hydrate_pubsub_rows(
                schema_names,
                lambda row, _payload: schemas_resource.get(resource_id=str(row).strip(), action_dict=api_actions),
            )
        elif not manual_schemas_requested:
            schemas = schemas_resource.list(project_id=project_id, action_dict=scope_actions) or []

            if args.get and schemas:
                schemas = _hydrate_pubsub_rows(
                    schemas,
                    lambda _row, payload: schemas_resource.get(
                        resource_id=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )

        if schemas:
            schemas_resource.save(schemas)
        if args.iam:
            schema_targets = schema_names if manual_schemas_requested else [
                str(schema.get("name") if isinstance(schema, dict) else getattr(schema, "name", "")).strip()
                for schema in schemas
                if str(schema.get("name") if isinstance(schema, dict) else getattr(schema, "name", "")).strip()
            ]
            for name in schema_targets:
                schemas_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

        show_schema_summary = bool(schemas) or not manual_schemas_requested
        if show_schema_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Pub/Sub Schemas",
                schemas,
                ["name", "schema_id", "type"],
                primary_resource="Schemas",
                primary_sort_key="schema_id",
                )
        elif args.get:
            print("[*] No Pub/Sub schemas found for the supplied --schema-names.")
        else:
            print("[*] Manual --schema-names supplied without --get; skipping schema summary.")

    if selected.get("snapshots", False):
        manual_snapshots_requested = bool(snapshot_names)
        snapshots = []

        if manual_snapshots_requested and args.get:
            snapshots = _hydrate_pubsub_rows(
                snapshot_names,
                lambda row, _payload: snapshots_resource.get(resource_id=str(row).strip(), action_dict=api_actions),
            )
        elif not manual_snapshots_requested:
            snapshots = snapshots_resource.list(project_id=project_id, action_dict=scope_actions) or []

            if args.get and snapshots:
                snapshots = _hydrate_pubsub_rows(
                    snapshots,
                    lambda _row, payload: snapshots_resource.get(
                        resource_id=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )

        if snapshots:
            snapshots_resource.save(snapshots)
        if args.iam:
            snapshot_targets = snapshot_names if manual_snapshots_requested else [
                str(snapshot.get("name") if isinstance(snapshot, dict) else getattr(snapshot, "name", "")).strip()
                for snapshot in snapshots
                if str(snapshot.get("name") if isinstance(snapshot, dict) else getattr(snapshot, "name", "")).strip()
            ]
            for name in snapshot_targets:
                snapshots_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

        show_snapshot_summary = bool(snapshots) or not manual_snapshots_requested
        if show_snapshot_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Pub/Sub Snapshots",
                snapshots,
                ["name", "snapshot_id", "topic", "expire_time"],
                primary_resource="Snapshots",
                primary_sort_key="snapshot_id",
                )
        elif args.get:
            print("[*] No Pub/Sub snapshots found for the supplied --snapshot-names.")
        else:
            print("[*] Manual --snapshot-names supplied without --get; skipping snapshot summary.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="pubsub_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="pubsub_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="pubsub_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )
    return 1
