from __future__ import annotations

import argparse


def run_module(user_args, session):
    parser = argparse.ArgumentParser(
        description="Analyze vulnerabilities from processed IAM bindings (coming soon).",
        allow_abbrev=False,
    )
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Reserved for future use.")
    parser.add_argument("--txt", action="store_true", help="Reserved for future use.")
    parser.add_argument("--csv", action="store_true", help="Reserved for future use.")
    parser.add_argument("--silent", action="store_true", help="Reserved for future use.")
    parser.add_argument("--output", required=False, help="Reserved for future use.")
    parser.parse_args(user_args)
    _ = session
    print("[*] analyze_vulns is coming soon.")
