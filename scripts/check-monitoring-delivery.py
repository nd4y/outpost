"""Exercise two independent notification paths on loopback in an isolated lab."""

import argparse
import base64
from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time


MONITOR = "synthetic-primary"
USER = "synthetic"
PASSWORD = secrets.token_urlsafe(24)
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


def verify_binary(path, expected):
    path = path.resolve(strict=True)
    with path.open("rb") as binary:
        actual = hashlib.file_digest(binary, "sha256").hexdigest()
    if not path.is_file() or actual != expected:
        raise ValueError(f"unexpected binary digest: {path.name}")
    return path


class Fixture:
    def __init__(self):
        self.lock = threading.Lock()
        self.blocked = 0
        self.last_heartbeat = None
        self.events = []

    def metrics(self, path):
        with self.lock:
            now = int(time.time())
            if path == "/primary-metrics":
                scope = 'outpost_node="node",outpost_domain="domain"'
                return (
                    f"outpost_expected_telemetry_max_age_seconds{{{scope}}} 6\n"
                    f"outpost_report_observed_timestamp_seconds{{{scope}}} {now} {now * 1000}\n"
                    f"outpost_inventory_available{{{scope}}} 1 {now * 1000}\n"
                    f"outpost_jobs_blocked{{{scope}}} {self.blocked} {now * 1000}\n"
                )
            scope = f'outpost_monitor="{MONITOR}"'
            metrics = f"outpost_expected_monitor_max_age_seconds{{{scope}}} 5\n"
            if self.last_heartbeat is not None:
                metrics += f"outpost_monitor_heartbeat_received_timestamp_seconds{{{scope}}} {self.last_heartbeat}\n"
            return metrics

    def receive(self, path, message):
        alert = message["commonLabels"]["alertname"]
        phase = message["status"]
        expected = {
            "/heartbeat": "OutpostMonitorHeartbeat",
            "/primary": "OutpostJobsBlocked",
            "/watchdog": "OutpostMonitoringDeliveryMissing",
        }
        if expected.get(path) != alert or phase not in ("firing", "resolved"):
            return False
        if message["commonLabels"].get("outpost_monitor") != MONITOR:
            return False
        with self.lock:
            if path == "/heartbeat" and phase == "firing":
                self.last_heartbeat = int(time.time())
            self.events.append((alert, phase))
        return True

    def count(self, alert, phase):
        with self.lock:
            return self.events.count((alert, phase))


def server_for(fixture):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path not in ("/primary-metrics", "/watchdog-metrics"):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(fixture.metrics(self.path).encode())

        def do_POST(self):
            if self.headers.get("Authorization") != AUTH:
                self.send_error(401)
                return
            try:
                length = int(self.headers["Content-Length"])
                message = json.loads(self.rfile.read(length)) if 0 < length <= 16384 else {}
                accepted = fixture.receive(self.path, message)
            except (KeyError, TypeError, ValueError):
                accepted = False
            self.send_response(204 if accepted else 400)
            self.end_headers()

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def reserve_ports(count):
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for connection in sockets:
            connection.bind(("127.0.0.1", 0))
        return [connection.getsockname()[1] for connection in sockets]


def wait_for(condition, description, seconds=24):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return
        time.sleep(0.1)
    raise AssertionError(description)


def stop(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def alertmanager_config(port, primary):
    def receiver(name):
        return {
            "name": name,
            "webhook_configs": [{
                "url": f"http://127.0.0.1:{port}/{name}",
                "send_resolved": True,
                "http_config": {"basic_auth": {"username": USER, "password": PASSWORD}},
            }],
        }

    route = {
        "receiver": "primary" if primary else "watchdog",
        "group_by": ["alertname", "outpost_node", "outpost_domain", "outpost_target", "outpost_monitor"],
        "group_wait": "0s",
        "group_interval": "1s",
        "repeat_interval": "1h",
    }
    receivers = [receiver(route["receiver"])]
    if primary:
        route["routes"] = [{
            "receiver": "heartbeat",
            "matchers": ['alertname="OutpostMonitorHeartbeat"'],
            "repeat_interval": "1s",
        }]
        receivers.append(receiver("heartbeat"))
    return {"route": route, "receivers": receivers}


def prometheus_config(rules, scrape_port, alert_port, primary):
    return {
        "global": {
            "scrape_interval": "1s", "scrape_timeout": "1s", "evaluation_interval": "1s",
            "external_labels": {"outpost_monitor": MONITOR} if primary else {},
        },
        "rule_files": [str(rules / ("outpost.rules.yml" if primary else "watchdog.rules.yml"))],
        "scrape_configs": [{
            "job_name": "fixture",
            "metrics_path": "/primary-metrics" if primary else "/watchdog-metrics",
            "static_configs": [{"targets": [f"127.0.0.1:{scrape_port}"]}],
        }],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [f"127.0.0.1:{alert_port}"]}]}]},
    }


def prometheus_args(data):
    return [f"--storage.tsdb.path={data}", "--rules.alert.resend-delay=1s"]


def test_delivery(prometheus, alertmanager, rules, work):
    fixture = Fixture()
    primary_prom, primary_am, watch_prom, watch_am = reserve_ports(4)
    logs = []
    with ExitStack() as stack:
        httpd = stack.enter_context(server_for(fixture))
        thread = threading.Thread(target=httpd.serve_forever)
        thread.start()
        stack.callback(thread.join)
        stack.callback(httpd.shutdown)

        def start(binary, name, config, port, extra):
            profile = work / f"{name}.json"
            profile.write_text(json.dumps(config), encoding="utf-8")
            data = work / name
            data.mkdir(exist_ok=True)
            log_path = work / f"{name}.log"
            logs.append(log_path)
            log = stack.enter_context(log_path.open("ab"))
            process = subprocess.Popen(
                [str(binary), f"--config.file={profile}", f"--web.listen-address=127.0.0.1:{port}", *extra(data)],
                stdout=log, stderr=log,
            )
            stack.callback(stop, process)
            return process

        def primary_notifier():
            return start(alertmanager, "primary-notifier", alertmanager_config(httpd.server_port, True), primary_am,
                         lambda data: ["--cluster.listen-address=", f"--storage.path={data}"])

        try:
            primary = primary_notifier()
            start(prometheus, "primary-evaluator", prometheus_config(rules, httpd.server_port, primary_am, True),
                  primary_prom, prometheus_args)
            wait_for(lambda: fixture.count("OutpostMonitorHeartbeat", "firing") > 0, "heartbeat was not delivered")
            start(alertmanager, "watchdog-notifier", alertmanager_config(httpd.server_port, False), watch_am,
                  lambda data: ["--cluster.listen-address=", f"--storage.path={data}"])
            start(prometheus, "watchdog-evaluator", prometheus_config(rules, httpd.server_port, watch_am, False),
                  watch_prom, prometheus_args)

            with fixture.lock:
                fixture.blocked = 1
            blocked = "OutpostJobsBlocked"
            delivery = "OutpostMonitoringDeliveryMissing"
            wait_for(lambda: fixture.count(blocked, "firing") == 1, "blocked-job alert was not delivered")
            time.sleep(4)
            if fixture.count(blocked, "firing") != 1 or fixture.count(delivery, "firing") != 0:
                raise AssertionError("unchanged state repeated or the healthy notification route was reported missing")
            with fixture.lock:
                fixture.blocked = 0
            wait_for(lambda: fixture.count(blocked, "resolved") == 1, "recovery was not delivered")

            stop(primary)
            wait_for(lambda: fixture.count(delivery, "firing") == 1, "independent route missed the notifier outage")
            primary_notifier()
            wait_for(lambda: fixture.count(delivery, "resolved") == 1, "independent route missed recovery")
            return {
                "blockedFiring": fixture.count(blocked, "firing"),
                "blockedResolved": fixture.count(blocked, "resolved"),
                "watchdogFiring": fixture.count(delivery, "firing"),
                "watchdogResolved": fixture.count(delivery, "resolved"),
                "heartbeatReceipts": fixture.count("OutpostMonitorHeartbeat", "firing"),
            }
        except Exception:
            for path in dict.fromkeys(logs):
                print(path.name, path.read_text(errors="replace").splitlines()[-8:])
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for tool in ("prometheus", "alertmanager"):
        parser.add_argument(f"--{tool}", type=Path, required=True)
        parser.add_argument(f"--{tool}-sha256", required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    prom = verify_binary(args.prometheus, args.prometheus_sha256)
    alerts = verify_binary(args.alertmanager, args.alertmanager_sha256)
    with tempfile.TemporaryDirectory(prefix="outpost-monitoring-", dir=args.work.resolve(strict=True)) as directory:
        print(json.dumps(test_delivery(prom, alerts, args.rules.resolve(strict=True), Path(directory))))
