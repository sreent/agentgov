#!/usr/bin/env python3
"""Run the Helm chart's pods with Docker, for hosts that can't run Kubernetes.

scripts/ci.sh --e2e uses it to check the chart at run time: it renders the chart
(helm template), then this script starts every Deployment and StatefulSet as a
kubelet would, as far as containers go:

* a pod's containers share one network namespace, reachable under the pod's
  Service name, and its volumes (emptyDir and claims as volumes without Docker's
  copy-up, configMaps as read-only files);
* init containers run to completion first;
* the pod's user and group, read-only root file systems, dropped capabilities
  and no-new-privileges apply as in the chart;
* environment variables resolve from the rendered Secret, $(VAR) references
  and the pod's name, as Kubernetes resolves them.

Readiness probes are honoured: the database, Keycloak and the control plane
start first, each once the one before is ready, and `up` returns when every pod
is ready. Network policies, ingresses and the scheduler are Kubernetes' own: the
kind check (scripts/ci.sh --kind) covers them where kind runs.

  chart-on-docker.py up RENDERED.yaml [--demo]   start (--demo: the demo MCP server)
  chart-on-docker.py secret RENDERED.yaml KEY    print a value of the chart's Secret
  chart-on-docker.py logs                        state and recent logs, for failures
  chart-on-docker.py down                        remove everything it started
"""

from __future__ import annotations

import base64
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

LABEL = "agentgov.chart-on-docker=1"
NETWORK = "agentgov-chart-on-docker"
HELPER = "alpine:3.22"
WORK = Path(__file__).resolve().parent.parent / ".venv" / "chart-on-docker"
# Host ports, as `kubectl port-forward` would give them (and as the demo expects).
PUBLISH = {
    "agentgov-control-plane": ["8000:8000"],
    "agentgov-gateway": ["8080:8080"],
    "agentgov-keycloak": ["8180:8080"],
    "agentgov-otel-collector": ["4318:4318"],
}
# Started in this order and waited for; the rest start together after them.
FIRST = ["agentgov-postgresql", "agentgov-keycloak", "agentgov-control-plane"]
READY_SECONDS = 600


def sh(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, check=False)  # noqa: S603
    if check and result.returncode != 0:
        sys.exit(f"failed: {' '.join(args)}\n{result.stderr[-2000:]}")
    return result


def load(path: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all(Path(path).read_text()) if d]


def secret_values(docs: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    return {
        d["metadata"]["name"]: {
            k: base64.b64decode(v).decode() for k, v in (d.get("data") or {}).items()
        }
        for d in docs
        if d["kind"] == "Secret"
    }


def resolve_env(container: dict[str, Any], pod: str, secrets: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for e in container.get("env") or []:
        if "value" in e:
            # Kubernetes expands $(VAR) from variables defined earlier in the list.
            value = re.sub(
                r"\$\((\w+)\)", lambda m: values.get(m.group(1), m.group(0)), str(e["value"])
            )
        elif "secretKeyRef" in e["valueFrom"]:
            ref = e["valueFrom"]["secretKeyRef"]
            value = secrets[ref["name"]][ref["key"]]
        elif e["valueFrom"].get("fieldRef", {}).get("fieldPath") == "metadata.name":
            value = pod
        else:
            sys.exit(f"{pod}: unsupported environment variable {e}")
        values[e["name"]] = value
    return values


def docker_run(
    container: dict[str, Any],
    name: str,
    *,
    pod: str,
    user: str,
    mounts: dict[str, str],
    secrets: dict[str, Any],
    detach: bool,
) -> list[str]:
    env = resolve_env(container, pod, secrets)
    args = ["docker", "run", "--name", name, "--label", LABEL, "--network", f"container:{pod}"]
    args += ["-d"] if detach else ["--rm"]
    if user:
        args += ["--user", user]
    security = container.get("securityContext") or {}
    if security.get("readOnlyRootFilesystem"):
        args.append("--read-only")
    if security.get("allowPrivilegeEscalation") is False:
        args += ["--security-opt", "no-new-privileges"]
    if "ALL" in ((security.get("capabilities") or {}).get("drop") or []):
        args += ["--cap-drop", "ALL"]
    for m in container.get("volumeMounts") or []:
        spec = f"{mounts[m['name']]},target={m['mountPath']}"
        if m.get("readOnly") or spec.startswith("type=bind"):
            spec += ",readonly"
        args += ["--mount", spec]
    for key, value in env.items():
        args += ["-e", f"{key}={value}"]

    def expand(items: list[str]) -> list[str]:
        return [
            re.sub(r"\$\((\w+)\)", lambda m: env.get(m.group(1), m.group(0)), item)
            for item in items
        ]

    command = container.get("command") or []
    if command:
        args += ["--entrypoint", command[0]]
    return [*args, container["image"], *expand(command[1:]), *expand(container.get("args") or [])]


def start_pod(workload: dict[str, Any], docs: list[dict[str, Any]]) -> None:
    pod = workload["metadata"]["name"]
    spec = workload["spec"]["template"]["spec"]
    security = spec.get("securityContext") or {}
    user = ""
    if "runAsUser" in security:
        user = f"{security['runAsUser']}:{security.get('runAsGroup', security['runAsUser'])}"
    secrets = secret_values(docs)
    configmaps = {d["metadata"]["name"]: d["data"] for d in docs if d["kind"] == "ConfigMap"}
    mounts: dict[str, str] = {}
    for volume in spec.get("volumes") or []:
        name = volume["name"]
        if "configMap" in volume:
            folder = WORK / pod / name
            folder.mkdir(parents=True, exist_ok=True)
            for key, content in configmaps[volume["configMap"]["name"]].items():
                (folder / key).write_text(content)
                (folder / key).chmod(0o644)
            folder.chmod(0o755)
            mounts[name] = f"type=bind,source={folder}"
        elif "emptyDir" in volume:
            # emptyDir: empty and writable by anyone, unlike a fresh Docker volume.
            mounts[name] = new_volume(f"{pod}-{name}", mode="1777")
        else:
            sys.exit(f"{pod}: unsupported volume {volume}")
    for claim in workload["spec"].get("volumeClaimTemplates") or []:
        group = security.get("fsGroup")
        mounts[claim["metadata"]["name"]] = new_volume(
            f"{pod}-{claim['metadata']['name']}", owner=f"{group}:{group}" if group else None
        )
    publish = [arg for port in PUBLISH.get(pod, []) for arg in ("-p", f"127.0.0.1:{port}")]
    # The pod's network namespace, under its Service's name.
    sh("docker", "run", "-d", "--name", pod, "--label", LABEL, "--network", NETWORK,
       "--network-alias", pod, *publish, "--entrypoint", "sleep", HELPER, "infinity")  # fmt: skip
    common = {"pod": pod, "user": user, "mounts": mounts, "secrets": secrets}
    for init in spec.get("initContainers") or []:
        print(f"{pod}: init container {init['name']}", flush=True)
        args = docker_run(init, f"{pod}-init-{init['name']}", detach=False, **common)
        if subprocess.run(args, check=False).returncode != 0:  # noqa: S603
            sys.exit(f"{pod}: init container {init['name']} failed")
    for container in spec["containers"]:
        print(f"{pod}: starting {container['name']}", flush=True)
        sh(*docker_run(container, f"{pod}-{container['name']}", detach=True, **common))


def new_volume(name: str, *, mode: str | None = None, owner: str | None = None) -> str:
    sh("docker", "volume", "create", "--label", LABEL, name)
    if mode:
        sh("docker", "run", "--rm", "-v", f"{name}:/v", HELPER, "chmod", mode, "/v")
    if owner:
        sh("docker", "run", "--rm", "-v", f"{name}:/v", HELPER, "chown", owner, "/v")
    # No copy-up: Kubernetes mounts volumes as they are, not seeded from the image.
    return f"type=volume,source={name},volume-nocopy"


def wait_ready(workload: dict[str, Any]) -> None:
    pod = workload["metadata"]["name"]
    container = workload["spec"]["template"]["spec"]["containers"][0]
    probe = container["readinessProbe"]
    ports = {p["name"]: p["containerPort"] for p in container.get("ports") or []}
    deadline = time.monotonic() + READY_SECONDS
    while time.monotonic() < deadline:
        probe_in_pod = ["docker", "run", "--rm", "--network", f"container:{pod}", HELPER]
        if "exec" in probe:
            check = ["docker", "exec", f"{pod}-{container['name']}", *probe["exec"]["command"]]
        elif "tcpSocket" in probe:
            port = ports.get(probe["tcpSocket"]["port"], probe["tcpSocket"]["port"])
            check = [*probe_in_pod, "nc", "-z", "127.0.0.1", str(port)]
        else:
            port = ports.get(probe["httpGet"]["port"], probe["httpGet"]["port"])
            url = f"http://127.0.0.1:{port}{probe['httpGet']['path']}"
            check = [*probe_in_pod, "wget", "-q", "-O", "/dev/null", url]
        if sh(*check, check=False).returncode == 0:
            print(f"{pod}: ready", flush=True)
            return
        state = sh("docker", "inspect", "-f", "{{.State.Status}}", f"{pod}-{container['name']}")
        if state.stdout.strip() != "running":
            sys.exit(f"{pod}: {container['name']} {state.stdout.strip()}")
        time.sleep(3)
    sys.exit(f"{pod}: not ready after {READY_SECONDS} seconds")


def up(rendered: str, demo: bool) -> None:
    docs = load(rendered)
    sh("docker", "network", "create", "--label", LABEL, NETWORK)
    workloads = [d for d in docs if d["kind"] in ("Deployment", "StatefulSet")]
    for name in FIRST:
        workload = next((w for w in workloads if w["metadata"]["name"] == name), None)
        if workload is not None:
            start_pod(workload, docs)
            wait_ready(workload)
    rest = [w for w in workloads if w["metadata"]["name"] not in FIRST]
    for workload in rest:
        start_pod(workload, docs)
    for workload in rest:
        wait_ready(workload)
    if demo:
        name, alias = "agentgov-demo-crm-mcp", "crm-mcp"  # the examples' tool server
        sh("docker", "run", "-d", "--name", name, "--label", LABEL, "--network", NETWORK,
           "--network-alias", alias, "agentgov-demo-crm:local")  # fmt: skip


def logs() -> None:
    names = sh("docker", "ps", "-a", "--filter", f"label={LABEL}", "--format", "{{.Names}}")
    for name in sorted(names.stdout.split()):
        state = sh("docker", "inspect", "-f", "{{.State.Status}}", name, check=False)
        print(f"--- {name}: {state.stdout.strip()}")
        out = sh("docker", "logs", "--tail", "40", name, check=False)
        print((out.stdout + out.stderr).strip())


def down() -> None:
    containers = sh("docker", "ps", "-aq", "--filter", f"label={LABEL}").stdout.split()
    if containers:
        sh("docker", "rm", "-f", *containers, check=False)
    volumes = sh("docker", "volume", "ls", "-q", "--filter", f"label={LABEL}").stdout.split()
    if volumes:
        sh("docker", "volume", "rm", *volumes, check=False)
    sh("docker", "network", "rm", NETWORK, check=False)
    shutil.rmtree(WORK, ignore_errors=True)


def main(argv: list[str]) -> None:
    match argv:
        case ["up", rendered, *flags] if set(flags) <= {"--demo"}:
            up(rendered, demo="--demo" in flags)
        case ["secret", rendered, key]:
            print(next(iter(secret_values(load(rendered)).values()))[key])
        case ["logs"]:
            logs()
        case ["down"]:
            down()
        case _:
            sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
