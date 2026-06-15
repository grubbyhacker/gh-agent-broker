#!/usr/bin/env python3
"""Log production deploy telemetry to the Actions log and tracking issue."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request


TRACKING_LABEL = "ssh-deploy-flakiness"
TRACKING_ISSUE_TITLE = "SSH deploy flakiness log"
TRACKING_ISSUE_BODY = "Durable log for production deploy SSH outcomes."


def warn(message: str) -> None:
    compact = " ".join(str(message).split())
    print(f"::warning::{compact[:1000]}")


def run_gh(args: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["gh", *args],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        warn("gh CLI is unavailable; deploy telemetry cannot be logged durably")
    except Exception as exc:  # noqa: BLE001 - telemetry must never fail deploys.
        warn(f"Unable to run gh {' '.join(args)}: {exc}")
    return None


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def fetch_text(url: str) -> str:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "gh-agent-broker-deploy-telemetry"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read(256).decode("utf-8", "replace").strip()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return f"error: {exc}"


def parse_ipv4(value: str) -> ipaddress.IPv4Address | None:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv4Address):
        return ip
    return None


def selected_runner_ip(ipify_value: str, ifconfig_value: str) -> ipaddress.IPv4Address | None:
    return parse_ipv4(ipify_value) or parse_ipv4(ifconfig_value)


def ip16(ip: ipaddress.IPv4Address | None) -> str:
    if ip is None:
        return "unknown"
    octets = str(ip).split(".")
    return ".".join(octets[:2])


def github_actions_ranges() -> list[str]:
    result = run_gh(["api", "meta", "--jq", ".actions[]"])
    if result is None:
        return []
    if result.returncode != 0:
        warn(f"Unable to fetch GitHub Actions IP ranges from meta API: {result.stderr.strip()}")
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def matched_actions_cidr(ip: ipaddress.IPv4Address | None, cidrs: list[str]) -> str:
    if ip is None:
        return "none"
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip.version == network.version and ip in network:
            return cidr
    return "none"


def parse_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def build_event() -> dict[str, object]:
    ts_utc = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    ipify_value = fetch_text("https://api.ipify.org")
    ifconfig_value = fetch_text("https://ifconfig.me")
    runner_ip = selected_runner_ip(ipify_value, ifconfig_value)
    actions_cidr = matched_actions_cidr(runner_ip, github_actions_ranges())

    event: dict[str, object] = {
        "outcome": env("DEPLOY_EVENT_OUTCOME", "failure"),
        "ts_utc": ts_utc,
        "runner_ip": {
            "api_ipify_org": ipify_value,
            "ifconfig_me": ifconfig_value,
        },
        "matched_actions_cidr": actions_cidr,
        "ip_16": ip16(runner_ip),
        "gh": {
            "run_id": env("DEPLOY_EVENT_RUN_ID", env("GITHUB_RUN_ID")),
            "run_attempt": env("DEPLOY_EVENT_RUN_ATTEMPT", env("GITHUB_RUN_ATTEMPT")),
            "job": env("DEPLOY_EVENT_JOB", env("GITHUB_JOB")),
            "workflow": env("DEPLOY_EVENT_WORKFLOW", env("GITHUB_WORKFLOW")),
            "runner_name": env("DEPLOY_EVENT_RUNNER_NAME"),
            "runner_env": env("DEPLOY_EVENT_RUNNER_ENV", env("RUNNER_ENVIRONMENT")),
        },
    }

    if event["outcome"] == "failure":
        event.update(
            {
                "ssh_error": env("DEPLOY_EVENT_SSH_ERROR"),
                "error_class": env("DEPLOY_EVENT_ERROR_CLASS", "other"),
                "time_to_fail_s": parse_int(env("DEPLOY_EVENT_TIME_TO_FAIL_S")),
                "tcp22": env("DEPLOY_EVENT_TCP22"),
                "mtr": env("DEPLOY_EVENT_MTR"),
            }
        )

    return event


def event_runner_ip(event: dict[str, object]) -> str:
    runner_ip = event.get("runner_ip")
    if not isinstance(runner_ip, dict):
        return "unknown"
    for key in ("api_ipify_org", "ifconfig_me"):
        value = runner_ip.get(key)
        if isinstance(value, str) and parse_ipv4(value):
            return value
    return "unknown"


def summary_line(event: dict[str, object]) -> str:
    runner = event_runner_ip(event)
    cidr = str(event.get("matched_actions_cidr", "none"))
    bucket = str(event.get("ip_16", "unknown"))
    attempt = str(event.get("gh", {}).get("run_attempt", "") if isinstance(event.get("gh"), dict) else "")
    ts_utc = str(event.get("ts_utc", ""))

    if event.get("outcome") == "success":
        return f"OK runner={runner} cidr={cidr} ip16={bucket} attempt={attempt} {ts_utc}"

    error_class = str(event.get("error_class", "other"))
    return f"FAIL {error_class} runner={runner} cidr={cidr} ip16={bucket} attempt={attempt} {ts_utc}"


def ensure_tracking_issue() -> str | None:
    label_result = run_gh(
        [
            "label",
            "list",
            "--repo",
            env("GITHUB_REPOSITORY"),
            "--search",
            TRACKING_LABEL,
            "--json",
            "name",
            "--jq",
            ".[].name",
        ]
    )
    if label_result is None:
        return None
    if label_result.returncode != 0:
        warn(f"Unable to list GitHub labels, durable deploy telemetry may not be logged: {label_result.stderr.strip()}")
    elif TRACKING_LABEL not in label_result.stdout.splitlines():
        create_label = run_gh(
            [
                "label",
                "create",
                TRACKING_LABEL,
                "--repo",
                env("GITHUB_REPOSITORY"),
                "--description",
                "Production deploy SSH outcome telemetry",
                "--color",
                "d73a4a",
            ]
        )
        if create_label is None:
            return None
        if create_label.returncode != 0:
            warn(f"Unable to create GitHub label '{TRACKING_LABEL}': {create_label.stderr.strip()}")

    issue_result = run_gh(
        [
            "issue",
            "list",
            "--repo",
            env("GITHUB_REPOSITORY"),
            "--state",
            "open",
            "--label",
            TRACKING_LABEL,
            "--json",
            "number",
            "--jq",
            ".[0].number // empty",
        ]
    )
    if issue_result is None:
        return None
    if issue_result.returncode != 0:
        warn(f"Unable to list deploy telemetry tracking issues: {issue_result.stderr.strip()}")
        return None

    issue_number = issue_result.stdout.strip()
    if issue_number:
        return issue_number

    create_issue = run_gh(
        [
            "issue",
            "create",
            "--repo",
            env("GITHUB_REPOSITORY"),
            "--title",
            TRACKING_ISSUE_TITLE,
            "--body",
            TRACKING_ISSUE_BODY,
            "--label",
            TRACKING_LABEL,
        ]
    )
    if create_issue is None:
        return None
    if create_issue.returncode != 0:
        warn(f"Unable to create deploy telemetry tracking issue: {create_issue.stderr.strip()}")
        return None
    return create_issue.stdout.strip().rstrip("/").split("/")[-1]


def post_comment(issue_number: str, body: str) -> None:
    result = run_gh(
        [
            "issue",
            "comment",
            issue_number,
            "--repo",
            env("GITHUB_REPOSITORY"),
            "--body",
            body,
        ]
    )
    if result is None:
        return
    if result.returncode != 0:
        warn(f"Unable to post deploy telemetry comment to issue #{issue_number}: {result.stderr.strip()}")
        return
    print(f"Posted deploy telemetry to issue #{issue_number}")


def main() -> int:
    try:
        event = build_event()
        event_json = json.dumps(event, indent=2)
        print("```json")
        print(event_json)
        print("```")

        body = f"{summary_line(event)}\n\n```json\n{event_json}\n```"
        issue_number = ensure_tracking_issue()
        if issue_number:
            post_comment(issue_number, body)
        else:
            warn("Skipping durable deploy telemetry comment because no tracking issue was available")
    except Exception as exc:  # noqa: BLE001 - telemetry must never fail deploys.
        warn(f"Deploy telemetry failed unexpectedly: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
