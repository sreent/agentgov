#!/usr/bin/env python3
"""Run the Helm chart's pods with Docker, for hosts that can't run Kubernetes.

scripts/ci.sh --e2e uses it to check the chart at run time: it renders the chart
(helm template), then this script starts every Deployment and StatefulSet as a
kubelet would, as far as containers go:

* a pod's containers share one network namespace, reachable under the pod's
  Service name, and its volumes (emptyDir and claims as volumes without Docker's
  copy-up, configMaps and Secrets as read-only files);
* a Deployment's replicas are pods of their own under the one Service name, which
  Docker's DNS spreads connections across; a Service published to the host gets a
  proxy that hands each connection to the next replica, as kube-proxy would;
* init containers run to completion first;
* the pod's user and group, read-only root file systems, dropped capabilities
  and no-new-privileges apply as in the chart;
* environment variables resolve from the rendered Secrets, $(VAR) references
  and the pod's name, as Kubernetes resolves them, and each Service's
  <NAME>_SERVICE_HOST, <NAME>_PORT and the like are set in every pod, as
  Kubernetes sets them, unless the pod turns service links off.

Readiness probes are honoured: the database, Keycloak and the control plane
start first, each once the one before is ready, and `up` returns when every pod
is ready. Network policies, ingresses and the scheduler are Kubernetes' own: the
kind check (scripts/ci.sh --kind) covers them where kind runs.

  chart-on-docker.py up RENDERED.yaml [--demo] [--tsa=DIR]
                                                 start (--demo: the demo MCP server, model,
                                                 workload identity issuer, the sink that
                                                 stands in for the security team's tools
                                                 and a time-stamping authority, with the
                                                 key and certificate in DIR, and the agent
                                                 other agents call)
  chart-on-docker.py secret RENDERED.yaml KEY    print KEY's value from the chart's Secrets
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
# The key the demo model accepts; scripts/ci.sh gives it to the chart (modelKeys).
DEMO_MODEL_KEY = "demo-model-key"
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
            **{k: base64.b64decode(v).decode() for k, v in (d.get("data") or {}).items()},
            **(d.get("stringData") or {}),
        }
        for d in docs
        if d["kind"] == "Secret"
    }


def service_links(docs: list[dict[str, Any]]) -> dict[str, str]:
    """The variables Kubernetes sets in a pod for each Service in its namespace (the
    Service's DNS name stands in for its cluster IP)."""
    links: dict[str, str] = {}
    for service in (d for d in docs if d["kind"] == "Service"):
        host = service["metadata"]["name"]
        name = host.upper().replace("-", "_")
        ports = service["spec"].get("ports") or []
        for i, port in enumerate(ports):
            proto = port.get("protocol", "TCP")
            address = f"{proto.lower()}://{host}:{port['port']}"
            if i == 0:
                links |= {
                    f"{name}_SERVICE_HOST": host,
                    f"{name}_SERVICE_PORT": str(port["port"]),
                    f"{name}_PORT": address,
                }
            if port.get("name"):
                links[f"{name}_SERVICE_PORT_{port['name'].upper().replace('-', '_')}"] = str(
                    port["port"]
                )
            prefix = f"{name}_PORT_{port['port']}_{proto}"
            links |= {
                prefix: address,
                f"{prefix}_PROTO": proto.lower(),
                f"{prefix}_PORT": str(port["port"]),
                f"{prefix}_ADDR": host,
            }
    return links


def resolve_env(
    container: dict[str, Any], pod: str, secrets: dict[str, Any], links: dict[str, str]
) -> dict[str, str]:
    # The container's own variables win over the Services' ones.
    values: dict[str, str] = dict(links)
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
    links: dict[str, str],
    detach: bool,
) -> list[str]:
    env = resolve_env(container, pod, secrets, links)
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


def replicas(workload: dict[str, Any]) -> int:
    return int(workload["spec"].get("replicas", 1)) if workload["kind"] == "Deployment" else 1


def pod_name(workload: dict[str, Any], replica: int) -> str:
    """The first replica's pod goes by its workload's (and Service's) name."""
    name = workload["metadata"]["name"]
    return name if replica == 0 else f"{name}-{replica}"


def start_pod(workload: dict[str, Any], docs: list[dict[str, Any]], replica: int = 0) -> None:
    service = workload["metadata"]["name"]
    pod = pod_name(workload, replica)
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
        elif "secret" in volume:
            source = volume["secret"]
            if source["secretName"] not in secrets and not source.get("optional"):
                sys.exit(f"{pod}: no Secret {source['secretName']}")
            folder = WORK / pod / name
            folder.mkdir(parents=True, exist_ok=True)
            values = secrets.get(source["secretName"], {})
            # With items, only those keys, each at its path.
            items = source.get("items") or [{"key": k, "path": k} for k in values]
            for item in items:
                (folder / item["path"]).write_text(values[item["key"]])
                (folder / item["path"]).chmod(0o644)
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
    # One replica publishes its Service's ports itself; several have a proxy (service()).
    ports = PUBLISH.get(service, []) if replicas(workload) == 1 else []
    publish = [arg for port in ports for arg in ("-p", f"127.0.0.1:{port}")]
    # The pod's network namespace, under its Service's name (and its own).
    aliases = ["--network-alias", service] + (["--network-alias", pod] if pod != service else [])
    sh("docker", "run", "-d", "--name", pod, "--label", LABEL, "--network", NETWORK,
       *aliases, *publish, "--entrypoint", "sleep", HELPER, "infinity")  # fmt: skip
    links = service_links(docs) if spec.get("enableServiceLinks", True) else {}
    common = {"pod": pod, "user": user, "mounts": mounts, "secrets": secrets, "links": links}
    for init in spec.get("initContainers") or []:
        print(f"{pod}: init container {init['name']}", flush=True)
        args = docker_run(init, f"{pod}-init-{init['name']}", detach=False, **common)
        if subprocess.run(args, check=False).returncode != 0:  # noqa: S603
            sys.exit(f"{pod}: init container {init['name']} failed")
    for container in spec["containers"]:
        print(f"{pod}: starting {container['name']}", flush=True)
        sh(*docker_run(container, f"{pod}-{container['name']}", detach=True, **common))


# A TCP proxy that hands each connection to the next of its targets (host:port), on the
# ports given; it runs with the workload's own image, which has Python.
PROXY = """
import asyncio, itertools, sys

targets = itertools.cycle(sys.argv[2:])


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def handle(reader, writer):
    host, port = next(targets).rsplit(":", 1)
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(host, int(port))
    except OSError:
        writer.close()
        return
    await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))


async def main():
    ports = [int(p) for p in sys.argv[1].split(",")]
    servers = [await asyncio.start_server(handle, "0.0.0.0", p) for p in ports]
    await asyncio.gather(*(s.serve_forever() for s in servers))


asyncio.run(main())
"""


def service(workload: dict[str, Any]) -> None:
    """Publish a Service of several replicas to the host, as one address."""
    name = workload["metadata"]["name"]
    ports = PUBLISH.get(name, [])
    if replicas(workload) == 1 or not ports:
        return
    image = workload["spec"]["template"]["spec"]["containers"][0]["image"]
    inside = [p.split(":")[1] for p in ports]
    targets = [
        f"{pod_name(workload, r)}:{port}" for port in inside for r in range(replicas(workload))
    ]
    publish = [arg for port in ports for arg in ("-p", f"127.0.0.1:{port}")]
    sh("docker", "run", "-d", "--name", f"{name}-service", "--label", LABEL,
       "--network", NETWORK, *publish, "--entrypoint", "python", image,
       "-c", PROXY, ",".join(inside), *targets)  # fmt: skip


def new_volume(name: str, *, mode: str | None = None, owner: str | None = None) -> str:
    sh("docker", "volume", "create", "--label", LABEL, name)
    if mode:
        sh("docker", "run", "--rm", "-v", f"{name}:/v", HELPER, "chmod", mode, "/v")
    if owner:
        sh("docker", "run", "--rm", "-v", f"{name}:/v", HELPER, "chown", owner, "/v")
    # No copy-up: Kubernetes mounts volumes as they are, not seeded from the image.
    return f"type=volume,source={name},volume-nocopy"


def wait_ready(workload: dict[str, Any], replica: int = 0) -> None:
    pod = pod_name(workload, replica)
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


def up(rendered: str, demo: bool, tsa: str | None = None) -> None:
    docs = load(rendered)
    sh("docker", "network", "create", "--label", LABEL, NETWORK)
    workloads = [d for d in docs if d["kind"] in ("Deployment", "StatefulSet")]
    for name in FIRST:
        workload = next((w for w in workloads if w["metadata"]["name"] == name), None)
        if workload is not None:
            for replica in range(replicas(workload)):
                start_pod(workload, docs, replica)
            for replica in range(replicas(workload)):
                wait_ready(workload, replica)
            service(workload)
    rest = [w for w in workloads if w["metadata"]["name"] not in FIRST]
    for workload in rest:
        for replica in range(replicas(workload)):
            start_pod(workload, docs, replica)
    for workload in rest:
        for replica in range(replicas(workload)):
            wait_ready(workload, replica)
        service(workload)
    if demo:
        # The examples' tool server and model provider.
        sh("docker", "run", "-d", "--name", "agentgov-demo-crm-mcp", "--label", LABEL,
           "--network", NETWORK, "--network-alias", "crm-mcp",
           "agentgov-demo-crm:local")  # fmt: skip
        sh("docker", "run", "-d", "--name", "agentgov-demo-model", "--label", LABEL,
           "--network", NETWORK, "--network-alias", "demo-model",
           "-e", f"MOCK_MODEL_KEY={DEMO_MODEL_KEY}", "agentgov-demo-model:local")  # fmt: skip
        # The stand-in cluster whose service account tokens agents authenticate with.
        sh("docker", "run", "-d", "--name", "agentgov-demo-workload-issuer", "--label", LABEL,
           "--network", NETWORK, "--network-alias", "workload-issuer", "-p", "9200:9200",
           "-e", "ISSUER=http://workload-issuer:9200", "agentgov-demo-issuer:local")  # fmt: skip
        # The security team's SIEM, Splunk, Slack and Teams (scripts/ci.sh gives the chart
        # their URLs and token as destinationSecrets), and the time-stamping authority, with
        # the key whose certificate the chart was given (controlPlane.timestamping).
        signing = ["-v", f"{Path(tsa).resolve()}:/tsa:ro", "-e", "TSA_DIR=/tsa"] if tsa else []
        sh("docker", "run", "-d", "--name", "agentgov-demo-sink", "--label", LABEL,
           "--network", NETWORK, "--network-alias", "demo-sink", "-p", "127.0.0.1:9300:9300",
           "-e", "HEC_TOKEN=demo-hec-token", *signing, "agentgov-demo-sink:local")  # fmt: skip
        # The agent other agents call over A2A, through the gateway (agents.yaml).
        sh("docker", "run", "-d", "--name", "agentgov-demo-billing-agent", "--label", LABEL,
           "--network", NETWORK, "--network-alias", "billing-agent",
           "-e", "GATEWAY_URL=http://agentgov-gateway:8080",
           "-e", "TOKEN_URL=http://agentgov-keycloak:8080/realms/agentgov/protocol/openid-connect/token",
           "-e", "ASSERTION_AUDIENCE=http://localhost:8180/realms/agentgov",
           "-e", "WORKLOAD_ISSUER=http://workload-issuer:9200",
           "-e", "DELEGATION_JWKS_URL=http://agentgov-control-plane:8000/v1/delegations/jwks",
           "agentgov-demo-billing:local")  # fmt: skip


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
        case ["up", rendered, *flags] if all(
            f == "--demo" or f.startswith("--tsa=") for f in flags
        ):
            tsa = next((f.removeprefix("--tsa=") for f in flags if f.startswith("--tsa=")), None)
            up(rendered, demo="--demo" in flags, tsa=tsa)
        case ["secret", rendered, key]:
            # The Secret that holds the key, of the several the chart renders (the
            # components' certificates and the bundle-signing key are Secrets too).
            held = [v[key] for v in secret_values(load(rendered)).values() if key in v]
            if not held:
                sys.exit(f"no Secret in {rendered} holds {key}")
            print(held[0])
        case ["logs"]:
            logs()
        case ["down"]:
            down()
        case _:
            sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
