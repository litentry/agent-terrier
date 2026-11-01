"""Explicit macOS real-model qualification with outbound networking denied."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from urllib.parse import urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import contracts, models, owner

REPOSITORY = Path(__file__).resolve().parents[2]
LOOPBACK_HOST = "127.0.0.1"
TEST_NETWORK_ADDRESS = "192.0.2.1"
OFFLINE_PROFILE = '(version 1) (allow default) (deny network-outbound) (allow network-outbound (remote ip "localhost:*")) (allow network-outbound (remote unix-socket))'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def build_gate_test():
    result = subprocess.run(["cargo", "test", "--offline", "-p", "agentkeys-gate", "--test",
        "local_configuration", "--no-run", "--message-format=json"], cwd=REPOSITORY,
        env=contracts.tool_environment(), capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError("Build the local_configuration relay test before offline qualification")
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    executables = [artifact["executable"] for artifact in artifacts
        if artifact.get("reason") == "compiler-artifact"
        and artifact.get("target", {}).get("name") == "local_configuration"
        and artifact.get("executable")]
    if len(executables) != 1:
        raise RuntimeError("Could not identify the compiled relay qualification")
    return executables[0]


def qualify_runtime_image(image, docker_socket, endpoint, environment, state):
    if not docker_socket.is_absolute() or not docker_socket.is_socket():
        raise ValueError("Container qualification requires an explicit local Docker socket")
    configuration = state / "docker-client"
    configuration.mkdir(mode=0o700)
    docker_environment = dict(environment, DOCKER_CONFIG=str(configuration))
    docker = ["docker", "--host", "unix://" + str(docker_socket)]

    def execute(arguments, timeout=60):
        result = subprocess.run([*docker, *arguments], env=docker_environment,
            capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("Container runtime qualification operation failed: " + result.stderr.strip())
        return result.stdout

    if not image or image.startswith("-") or any(character.isspace() for character in image):
        raise ValueError("Invalid qualification image reference")
    metadata = json.loads(execute(["image", "inspect", image]))[0]
    identity = metadata["Id"]
    namespace = "terrier-model-check-" + uuid.uuid4().hex
    transport = None
    transport_log = (state / "service-transport.log").open("wb")
    try:
        container = execute(["run", "--detach", "--pull=never", "--name", namespace,
            "--label", "org.agent-terrier.qualification=" + namespace, "--network=none",
            "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user=1000:1000", "--pids-limit=256",
            "--memory=512m", "--cpus=1", "--tmpfs=/tmp:rw,nosuid,nodev,size=128m",
            "--entrypoint", "node", identity, "-e", "setInterval(() => {}, 2147483647)"]).strip()
        inspected = json.loads(execute(["container", "inspect", container]))[0]
        if (inspected["HostConfig"]["NetworkMode"] != "none" or inspected["NetworkSettings"]["Ports"]
                or inspected["HostConfig"]["Binds"] or not inspected["HostConfig"]["ReadonlyRootfs"]):
            raise RuntimeError("Qualification container isolation differs from the requested configuration")
        denial = json.loads(execute(["exec", container, "node", "--input-type=module", "-e",
            "import net from 'node:net';const socket=net.connect(443,process.argv[1]);"
            "socket.setTimeout(3000,()=>{socket.destroy();process.exitCode=2});"
            "socket.on('connect',()=>{socket.destroy();process.exitCode=3});"
            "socket.on('error',error=>{console.log(JSON.stringify({code:error.code}));"
            "if(!['ENETUNREACH','ENETDOWN'].includes(error.code))process.exitCode=4});", TEST_NETWORK_ADDRESS]))
        transport = subprocess.Popen(["node", str(REPOSITORY / "packages/agent-terrier-runtime/service-transport.mjs"),
            "host", "--socket", str(docker_socket), "--container", container,
            "--targets", json.dumps({"model": endpoint + "/v1"})], env=docker_environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=transport_log)
        with selectors.DefaultSelector() as selector:
            selector.register(transport.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=15):
                raise RuntimeError("Local service transport readiness timed out")
        ready = json.loads(transport.stdout.readline(4097))
        if ready.get("protocol") != 1 or set(ready.get("endpoints", {})) != {"model"}:
            raise RuntimeError("Invalid local service transport readiness")
        report = execute(["exec", container, "node", "packages/agent-terrier-runtime/qualify-model.mjs",
            "--model-endpoint", ready["endpoints"]["model"]], timeout=180)
        return dict(json.loads(report), image_id=identity, image_platform=metadata["Os"] + "/" + metadata["Architecture"],
            container_network="none", external_connection_error=denial["code"], published_ports=False, host_mounts=False)
    finally:
        if transport:
            transport.stdin.close()
            try:
                transport.wait(timeout=5)
            except subprocess.TimeoutExpired:
                transport.kill()
                transport.wait(timeout=5)
            transport.stdout.close()
        transport_log.close()
        containers = execute(["container", "ls", "--all", "--quiet", "--filter",
            "label=org.agent-terrier.qualification=" + namespace]).split()
        for container in containers:
            execute(["container", "rm", "--force", container])


def qualify(model_directory, binary, gate=False, agent_runtime=False, runtime_image=None, docker_socket=None, application=False, solc=None):
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        raise ValueError("This offline qualification requires macOS sandbox-exec; the model probe itself is portable")
    recipe = models.run(REPOSITORY, "config")
    if recipe != json.loads((REPOSITORY / "presets/local-models.json").read_text()):
        raise ValueError("Rebuild the CLI: its model recipe differs from the checked-in source")
    model_directory = model_directory.expanduser().resolve(strict=True)
    compiler = contracts.validate_compiler(REPOSITORY / "crates/agentkeys-chain", solc) if application else None
    gate_test = build_gate_test() if gate else None
    with tempfile.TemporaryDirectory(prefix="terrier-model-qualification-") as temporary:
        state = Path(temporary)
        runtime_home = state / "home"
        runtime_home.mkdir(mode=0o700)
        profile = state / "offline.sb"
        profile.write_text(OFFLINE_PROFILE)
        restriction = [shutil.which("sandbox-exec"), "-f", str(profile)]
        environment = {key:value for key,value in contracts.tool_environment().items()
                       if key in ("PATH", "TMPDIR", "LANG", "LC_ALL")}
        environment["HOME"] = str(runtime_home)
        control = subprocess.run([*restriction, sys.executable, "-c",
            "import socket,sys\ns=socket.socket();s.settimeout(2)\ntry:s.connect((sys.argv[1],443))\nexcept PermissionError:sys.exit(0)\nexcept OSError:sys.exit(2)\nelse:sys.exit(3)",
            TEST_NETWORK_ADDRESS], env=environment, capture_output=True, timeout=5)
        if control.returncode:
            raise RuntimeError("Could not prove OS-level outbound connection denial")
        selected_port = 0
        if application:
            configured = urlsplit(recipe["base_url"])
            if configured.scheme != "http" or configured.hostname != LOOPBACK_HOST or configured.path != "/v1" or not configured.port:
                raise ValueError("Application qualification requires the recipe's explicit loopback model endpoint")
            selected_port = configured.port
        with socket.socket() as listener:
            listener.bind((LOOPBACK_HOST, selected_port))
            port = listener.getsockname()[1]
        endpoint = f"http://{LOOPBACK_HOST}:{port}"
        runtime = recipe["runtime"]
        environment.update(OLLAMA_HOST=f"{LOOPBACK_HOST}:{port}", OLLAMA_MODELS=str(model_directory),
            OLLAMA_NO_CLOUD="1", OLLAMA_NOPRUNE="1", OLLAMA_CONTEXT_LENGTH=str(runtime["context_length"]),
            OLLAMA_NUM_PARALLEL=str(runtime["parallel_requests"]), OLLAMA_MAX_LOADED_MODELS=str(runtime["max_loaded_models"]))
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

        def request(path):
            with client.open(endpoint+path, timeout=2) as response:
                return json.load(response)

        with (state / "runner.log").open("wb") as log:
            started = time.monotonic()
            process = subprocess.Popen([*restriction, binary, "serve"], env=environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, umask=0o077)
            peak_rss = [0]
            finished = threading.Event()

            def sample_memory():
                while not finished.is_set():
                    rows = [tuple(map(int,line.split())) for line in subprocess.check_output(
                        ["ps","-axo","pid=,ppid=,rss="],text=True).splitlines() if line.strip()]
                    owned = {process.pid}
                    for _ in range(4):
                        owned.update(pid for pid,parent,rss in rows if parent in owned)
                    peak_rss[0] = max(peak_rss[0],sum(rss for pid,parent,rss in rows if pid in owned))
                    finished.wait(0.5)

            sampler = threading.Thread(target=sample_memory)
            sampler.start()
            try:
                deadline = started + 60
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("Owned local runner exited before becoming ready")
                    try:
                        version = request("/api/version")["version"]
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Local model runner did not become ready in 60 seconds") from None
                        time.sleep(0.1)
                startup_seconds = time.monotonic()-started
                if version != runtime["version"]:
                    raise ValueError(f"Runner version {version} differs from qualified recipe {runtime['version']}")
                installed = {item["name"]:item for item in request("/api/tags")["models"]}
                for selection in (recipe["chat"],recipe["embedding"]):
                    if installed.get(selection["model"],{}).get("digest") != selection["digest"]:
                        raise ValueError(f"Missing or changed model: {selection['model']}; download and verify the pinned recipe first")
                probe_started = time.monotonic()
                result = subprocess.run([*restriction,str(owner.executable(REPOSITORY)),"models","probe",
                    "--base-url",endpoint+"/v1"], env=environment, capture_output=True,text=True,timeout=600)
                if result.returncode:
                    raise RuntimeError(result.stderr.strip())
                capabilities = json.loads(result.stdout)
                if capabilities["embedding_dimensions"] != recipe["embedding"]["dimension"]:
                    raise ValueError("Observed embedding dimension differs from the pinned recipe")
                probe_seconds = time.monotonic()-probe_started
                relay_report = None
                relay_seconds = None
                if gate_test:
                    relay_started = time.monotonic()
                    gate_environment = dict(environment, AGENT_TERRIER_MODEL_ENDPOINT=endpoint+"/v1")
                    gate_result = subprocess.run([*restriction, gate_test,
                        "real_local_models_through_authenticated_gate", "--exact", "--ignored", "--nocapture"],
                        env=gate_environment, capture_output=True, text=True, timeout=600)
                    if gate_result.returncode:
                        raise RuntimeError("Authenticated local relay qualification failed: "+gate_result.stderr.strip())
                    reports = [json.loads(line) for line in gate_result.stdout.splitlines() if line.startswith("{")]
                    if len(reports) != 1:
                        raise RuntimeError("Missing relay capability report")
                    relay_report = reports[0]
                    if relay_report["embedding_dimensions"] != recipe["embedding"]["dimension"]:
                        raise ValueError("Relay embedding dimension differs from the pinned recipe")
                    relay_seconds = round(time.monotonic()-relay_started,3)
                agent_report = None
                if agent_runtime:
                    agent_result = subprocess.run([*restriction, "node",
                        str(REPOSITORY / "packages/agent-terrier-runtime/qualify-model.mjs"),
                        "--model-endpoint", endpoint + "/v1"], cwd=REPOSITORY, env=environment,
                        capture_output=True, text=True, timeout=180)
                    if agent_result.returncode:
                        raise RuntimeError("Real agent runtime qualification failed: " + agent_result.stderr.strip())
                    agent_report = json.loads(agent_result.stdout)
                image_report = qualify_runtime_image(runtime_image, docker_socket, endpoint, environment, state) if runtime_image and not application else None
                application_report = None
                application_seconds = None
                if application:
                    application_started = time.monotonic()
                    application_environment = dict(environment, AGENT_TERRIER_TEST_MODEL_CHAT="1", AGENT_TERRIER_SOLC=str(compiler),
                        AGENT_TERRIER_TEST_AGENT_IMAGE=runtime_image,
                        AGENT_TERRIER_TEST_DOCKER_SOCKET=str(docker_socket),
                        AGENT_TERRIER_CACHE_DIR=str(contracts.cache_directory()))
                    application_result = subprocess.run([*restriction, sys.executable,
                        str(REPOSITORY / "scripts/tests/qualify_local_agents.py")], cwd=REPOSITORY,
                        env=application_environment, capture_output=True, text=True, timeout=600)
                    if application_result.returncode:
                        raise RuntimeError("Managed local application qualification failed: " + application_result.stderr.strip())
                    application_report = json.loads(application_result.stdout)
                    application_seconds = round(time.monotonic() - application_started, 3)
                return {
                    "qualification":"local-agent-application" if application else "local-model-capabilities", "external_network_denied":True,
                    "local_unix_control_sockets_allowed":True,
                    "solidity_compiler_sha256":hashlib.sha256(compiler.read_bytes()).hexdigest() if compiler else None,
                    "operating_system":platform.mac_ver()[0], "architecture":platform.machine(),
                    "hardware":subprocess.check_output(["sysctl","-n","machdep.cpu.brand_string"],text=True).strip(),
                    "physical_memory_bytes":int(subprocess.check_output(["sysctl","-n","hw.memsize"],text=True)),
                    "runtime_version":version, "recipe":recipe,
                    "model_bytes":sum(installed[recipe[key]["model"]]["size"] for key in ("chat","embedding")),
                    "runner_startup_seconds":round(startup_seconds,3),
                    "probe_seconds":round(probe_seconds,3),
                    "peak_runner_process_rss_kib":peak_rss[0], "capabilities":capabilities,
                    "authenticated_relay":relay_report,
                    "relay_probe_seconds":relay_seconds,
                    "agent_runtime":agent_report,
                    "agent_runtime_image":image_report,
                    "application":application_report, "application_seconds":application_seconds,
                }
            finally:
                finished.set()
                sampler.join()
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid,signal.SIGKILL)
                        process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir",type=Path,required=True,help="Existing downloaded model directory; no downloads or pruning")
    parser.add_argument("--ollama",default=shutil.which("ollama"),help="Local Ollama executable")
    parser.add_argument("--gate",action="store_true",help="Also qualify the authenticated relay using the same real models and network restriction")
    parser.add_argument("--agent-runtime",action="store_true",help="Also qualify real agent chat and restart recall; build the packages workspace first")
    parser.add_argument("--runtime-image",help="Reviewed preloaded runtime image; use the complete image with --application")
    parser.add_argument("--solc", type=Path, help="Explicit downloaded Solidity compiler for --application")
    parser.add_argument("--application", action="store_true", help="Qualify real owner-to-agent chat, restart recall and revocation through the complete local stack")
    parser.add_argument("--docker-socket",type=Path,help="Explicit local Docker socket required with --runtime-image")
    arguments = parser.parse_args()
    try:
        if not arguments.ollama:
            raise ValueError("Install the recipe's Ollama version first")
        if arguments.application and not (arguments.runtime_image and arguments.docker_socket and arguments.solc):
            raise ValueError("--application requires the complete runtime image, explicit Docker socket and downloaded --solc compiler")
        if arguments.solc and not arguments.application:
            raise ValueError("--solc is only used with --application")
        if bool(arguments.runtime_image) != bool(arguments.docker_socket):
            raise ValueError("Set --runtime-image and --docker-socket together")
        print(json.dumps(qualify(arguments.models_dir,arguments.ollama,arguments.gate,arguments.agent_runtime,
            arguments.runtime_image,arguments.docker_socket,arguments.application,arguments.solc),indent=2))
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        print(f"model qualification: {error}",file=sys.stderr)
        raise SystemExit(1)
