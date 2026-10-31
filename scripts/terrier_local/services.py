import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

from . import chain, contracts, deployment, local_state

SOCKET_NAME = "services.sock"
START_TIMEOUT = 45
CHILD_START_TIMEOUT = 10
STOP_TIMEOUT = 10
HEALTH_TIMEOUT = 1
RECORD_LIMIT = 4096
WORKERS = {
    "credentials": "agentkeys-worker-creds",
    "config": "agentkeys-worker-config",
    "memory": "agentkeys-worker-memory",
    "channel": "agentkeys-worker-channel",
}
BROKER_BINARY = "agentkeys-broker-server"
STORE_BINARY = "agentkeys-local-store"
SIGNER_BINARY = "agentkeys-local-signer"
RELAY_BINARY = "agentkeys-gate"
BUNDLER_BINARY = "agentkeys-bundler"
BINARIES = (BROKER_BINARY, STORE_BINARY, SIGNER_BINARY, RELAY_BINARY, BUNDLER_BINARY, *WORKERS.values())
MANIFEST_VERSION = 4


def binary_directory(repository, configured=None):
    directory = Path(configured or os.environ.get("AGENT_TERRIER_BIN_DIR", repository / "target/debug")).resolve()
    for name in BINARIES:
        if not (directory / name).is_file() or not os.access(directory / name, os.X_OK):
            raise ValueError(f"Build the local service binary {name} or configure --bin-dir")
    return directory


def status(state):
    return chain.control(state, "status", SOCKET_NAME)


def stop(state):
    return chain.control(state, "stop", SOCKET_NAME)


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def prepare(repository, state, binaries, port):
    running_chain, profile, fingerprint = deployment.active_profile(repository, state)
    directory = local_state.private_directory(state / "services")
    manifest_path = directory / "manifest.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        manifest = local_state.read_json(manifest_path)
        if (not isinstance(manifest, dict) or manifest.get("version") not in (1, 2, 3, MANIFEST_VERSION) or manifest.get("development_only") is not True
                or manifest.get("profile_identity") != fingerprint
                or type(manifest.get("initialized")) is not bool
                or type(manifest.get("broker_port")) is not int
                or not 1 <= manifest["broker_port"] <= 65535):
            raise ValueError("Service state belongs to another deployment or has an invalid manifest")
        if port is not None and port != manifest["broker_port"]:
            raise ValueError("The broker port is bound to existing service sessions; retain it or explicitly migrate the state")
    else:
        if any(directory.iterdir()):
            raise ValueError("Service manifest is missing; restore it before reusing existing state")
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("Broker port must be between 1 and 65535")
        manifest = {"version":MANIFEST_VERSION, "development_only":True, "profile_identity":fingerprint,
                    "broker_port":port if port is not None else available_port(), "initialized":False}
        local_state.write_json(manifest_path, manifest)
    broker_directory = local_state.private_directory(directory / "broker")
    for purpose in ("oidc", "session"):
        path = broker_directory / f"{purpose}.json"
        if path.exists() or path.is_symlink():
            os.close(local_state.open_private(path))
        elif manifest["initialized"]:
            raise ValueError("An existing broker signing key is missing; restore the original key")
        else:
            result = subprocess.run([str(binaries / BROKER_BINARY), "keygen", "--purpose", purpose, "--out", str(path)],
                env=contracts.tool_environment(), capture_output=True, timeout=15, umask=0o077)
            if result.returncode:
                raise RuntimeError("Local broker signing-key creation failed")
    public_key = broker_directory / "session-public.pem"
    if public_key.exists() or public_key.is_symlink():
        metadata = public_key.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or metadata.st_mode & 0o022):
            raise ValueError("Broker public-key output is unsafe")
    for data_class in WORKERS:
        worker_directory = local_state.private_directory(directory / data_class)
        key = worker_directory / "development.key"
        if key.exists() or key.is_symlink():
            os.close(local_state.open_private(key))
        elif manifest["initialized"]:
            raise ValueError("An existing worker encryption key is missing; restore the original key")
        else:
            local_state.write_private(key, secrets.token_hex(32).encode())
    signer_directory = local_state.private_directory(directory / "signer")
    signer_secret = signer_directory / "master.key"
    if signer_secret.exists() or signer_secret.is_symlink():
        os.close(local_state.open_private(signer_secret))
    elif manifest["initialized"] and manifest["version"] >= 2:
        raise ValueError("An existing development signer key is missing; restore the original key")
    else:
        local_state.write_private(signer_secret, secrets.token_hex(32).encode())
    relay_directory = local_state.private_directory(directory / "relay")
    for name in ("admin.key", "keys.json"):
        path = relay_directory / name
        if path.exists() or path.is_symlink():
            os.close(local_state.open_private(path))
        elif manifest["initialized"] and manifest["version"] >= 3:
            raise ValueError("Existing model relay state is missing; restore the original file")
        elif name == "admin.key":
            local_state.write_private(path, secrets.token_hex(32).encode())
        else:
            local_state.write_json(path, {})
    prepare_submitter(state, binaries, manifest, running_chain, profile)
    manifest["version"] = MANIFEST_VERSION
    manifest["initialized"] = True
    local_state.write_json(manifest_path, manifest)
    return manifest


def prepare_submitter(state, binaries, manifest, running_chain, profile):
    bundler_directory = local_state.private_directory(state / "services/bundler")
    bundler_key = bundler_directory / "submitter.key"
    arguments = [str(binaries / BUNDLER_BINARY), "--development", "--profile", str(state / "chain-profile.json")]
    if bundler_key.exists() or bundler_key.is_symlink():
        os.close(local_state.open_private(bundler_key))
        arguments.extend(["--signer-key-file", str(bundler_key), "address"])
    elif manifest["initialized"] and manifest["version"] >= 4:
        raise ValueError("An existing transaction submitter key is missing; restore the original key")
    else:
        arguments.extend(["keygen", "--out", str(bundler_key)])
    result = subprocess.run(arguments, env=contracts.tool_environment(), capture_output=True, timeout=15, umask=0o077)
    if result.returncode:
        raise RuntimeError("Local transaction submitter key could not be created or verified")
    identity = json.loads(result.stdout)
    address = identity.get("address")
    if identity.get("development_only") is not True or not deployment.valid_address(address):
        raise ValueError("Local transaction submitter returned an invalid identity")
    chain.node_identity(running_chain["rpc_http"], profile["chain_id"], running_chain["instance_id"])
    funding = int(profile["funding"]["account_deposit_wei"])
    balance = int(chain.rpc(running_chain["rpc_http"], "eth_getBalance", [address, "latest"]), 16)
    if balance < funding:
        chain.rpc(running_chain["rpc_http"], "anvil_setBalance", [address, hex(funding)])


def start(repository, state, configured=None, port=None):
    current = status(state)
    if current["running"]:
        if current.get("service_schema") != MANIFEST_VERSION:
            raise RuntimeError("The running services use an older schema; stop and restart them to migrate")
        if not current.get("ready"):
            raise RuntimeError("Local services are unhealthy; inspect doctor/logs, then stop before restarting")
        if port is not None and current["broker_port"] != port:
            raise ValueError("The owned broker is already running on a different port")
        return current
    binaries = binary_directory(repository, configured)
    prepare(repository, state, binaries, port)
    log = local_state.open_private(state / "services-supervisor.log", os.O_CREAT | os.O_WRONLY | os.O_APPEND)
    environment = contracts.tool_environment()
    environment["AGENT_TERRIER_STATE_DIR"] = str(state)
    try:
        supervisor = subprocess.Popen([sys.executable, str(repository / "terrier"), "_serve-services",
            "--bin-dir", str(binaries)], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            env=environment, start_new_session=True, umask=0o077)
    finally:
        os.close(log)
    try:
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            current = status(state)
            if current["running"]:
                if not current.get("ready"):
                    raise RuntimeError("Local services failed their startup health checks; inspect services logs")
                return current
            if supervisor.poll() is not None:
                raise RuntimeError("Local services could not start; inspect services logs")
            time.sleep(0.1)
        raise RuntimeError("Local services startup timed out; inspect services logs")
    except BaseException:
        stop_children([supervisor])
        raise


def stop_children(children):
    for process in children:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + STOP_TIMEOUT
    for process in children:
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        if process.stdout:
            process.stdout.close()


def broker_environment(directory, profile, port):
    environment = contracts.tool_environment()
    environment.update(BROKER_OIDC_ISSUER=f"http://127.0.0.1:{port}",
        BROKER_DEV_MODE="true", BROKER_SHUTDOWN_GRACE_SECONDS="0",
        BROKER_AUDIT_DB_PATH=str(directory / "audit.sqlite"),
        BROKER_OIDC_KEYPAIR_PATH=str(directory / "oidc.json"),
        BROKER_SESSION_KEYPAIR_PATH=str(directory / "session.json"),
        AGENTKEYS_CHAIN_PROFILE_FILE=str(profile))
    return environment


def broker_arguments(directory, port):
    return ["--port", str(port), "--export-session-pubkey-to", str(directory / "session-public.pem")]


def launch(binary, arguments, environment, log_path, children):
    log = local_state.open_private(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND)
    try:
        process = subprocess.Popen([str(binary), *map(str, arguments)], env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log, text=True, umask=0o077)
    finally:
        os.close(log)
    children.append(process)
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=CHILD_START_TIMEOUT):
            raise RuntimeError(f"{binary.name} did not announce readiness")
        record = process.stdout.readline(RECORD_LIMIT + 1)
    if not record or len(record) > RECORD_LIMIT or not record.endswith("\n"):
        raise RuntimeError(f"{binary.name} returned an invalid startup record")
    record = json.loads(record)
    if not isinstance(record, dict) or not isinstance(record.get("listen"), str):
        raise ValueError("Local service returned an invalid listener record")
    address = record["listen"]
    host, separator, port = address.rpartition(":")
    if host != "127.0.0.1" or not separator or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("Local service announced a non-loopback listener")
    return process, "http://" + address


def healthy(endpoint, broker=False):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), chain.NoRedirect())
    try:
        with opener.open(endpoint + ("/readyz" if broker else "/healthz"), timeout=HEALTH_TIMEOUT) as response:
            data = response.read(RECORD_LIMIT + 1)
            if len(data) > RECORD_LIMIT:
                return False
            result = json.loads(data)
            return response.status == 200 and (result.get("status") == "ready" if broker
                                               else result.get("ready", result.get("ok")) is True)
    except (OSError, ValueError, urllib.error.URLError):
        return False


def serve(repository, state, configured):
    os.umask(0o077)
    with local_state.exclusive_lock(state / "services.lock"):
        binaries = binary_directory(repository, configured)
        manifest = prepare(repository, state, binaries, None)
        directory = state / "services"
        profile_path = state / "chain-profile.json"
        broker_directory = directory / "broker"
        public_key = broker_directory / "session-public.pem"
        children = []
        components = {}
        path = chain.socket_path(state, SOCKET_NAME)
        bound = False

        def interrupted(_signal, _frame):
            raise InterruptedError("Local services supervisor stopped")

        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        try:
            relay_directory = directory / "relay"
            components["model_relay"] = launch(binaries / RELAY_BINARY,
                ["--listen", "127.0.0.1:0", "--require-local-upstream",
                 "--admin-token-file", relay_directory / "admin.key", "--keys-file", relay_directory / "keys.json"],
                contracts.tool_environment(), directory / "model-relay.log", children)
            components["bundler"] = launch(binaries / BUNDLER_BINARY,
                ["--development", "--profile", profile_path, "--bind", "127.0.0.1:0",
                 "--signer-key-file", directory / "bundler/submitter.key"],
                contracts.tool_environment(), directory / "bundler.log", children)
            environment = broker_environment(broker_directory, profile_path, manifest["broker_port"])
            environment.update(AGENTKEYS_GATE_ADMIN_URL=components["model_relay"][1],
                AGENTKEYS_GATE_ADMIN_TOKEN_FILE=str(relay_directory / "admin.key"),
                AGENTKEYS_GATE_TURN_URL=components["model_relay"][1] + "/v1", AGENTKEYS_BUNDLER_URL=components["bundler"][1])
            components["broker"] = launch(binaries / BROKER_BINARY,
                broker_arguments(broker_directory, manifest["broker_port"]),
                environment, directory / "broker.log", children)
            if components["broker"][1] != environment["BROKER_OIDC_ISSUER"]:
                raise ValueError("Broker listener differs from the persisted session issuer")
            components["signer"] = launch(binaries / SIGNER_BINARY,
                ["--development", "--profile", profile_path, "--broker-public-key", public_key,
                 "--master-secret-file", directory / "signer/master.key"],
                contracts.tool_environment(), directory / "signer.log", children)
            for data_class, worker_binary in WORKERS.items():
                worker_directory = directory / data_class
                common = ["--development", "--profile", profile_path, "--broker-public-key", public_key]
                store = launch(binaries / STORE_BINARY,
                    [*common, "--database", worker_directory / "objects.db", "--data-class", data_class],
                    contracts.tool_environment(), directory / f"{data_class}-store.log", children)
                components[data_class + "_store"] = store
                components[data_class] = launch(binaries / worker_binary,
                    [*common, "--storage-url", store[1], "--development-kek-file", worker_directory / "development.key"],
                    contracts.tool_environment(), directory / f"{data_class}.log", children)

            def snapshot():
                services = {name:{"url":endpoint, "healthy":process.poll() is None and healthy(endpoint, name in ("broker", "model_relay"))}
                            for name, (process, endpoint) in components.items()}
                running_chain = chain.status(state)
                profile = local_state.read_json(profile_path)
                profile_matches = (deployment.profile_identity(profile) == manifest["profile_identity"]
                                   and profile.get("rpc", {}).get("http") == running_chain.get("rpc_http")
                                   and profile.get("contract_set_version") ==
                                   (repository / "crates/agentkeys-chain/VERSION").read_text().strip())
                return {"running":True, "service_schema":MANIFEST_VERSION, "ready":running_chain["running"] and profile_matches and all(item["healthy"] for item in services.values()),
                        "development_only":True, "broker_port":manifest["broker_port"],
                        "chain_running":running_chain["running"], "profile_matches":profile_matches, "services":services}

            if not snapshot()["ready"]:
                raise RuntimeError("Local service health check failed")
            if path.exists() or path.is_symlink():
                chain.validate_socket(path)
                path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                bound = True
                path.chmod(0o600)
                listener.listen(4)
                listener.settimeout(0.5)
                while True:
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(chain.RPC_TIMEOUT)
                        stopped = False
                        try:
                            request = chain.receive_message(connection)
                            if request.get("action") == "stop":
                                stop_children(children)
                                stopped = True
                                result = {"running":False, "ready":False, "state_preserved":True}
                            elif request.get("action") == "status":
                                result = snapshot()
                            else:
                                raise ValueError("Unsupported local service action")
                        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                            result = {"error":str(error)}
                        try:
                            connection.sendall((json.dumps(result) + "\n").encode())
                        except OSError:
                            pass
                        if stopped:
                            return 0
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            stop_children(children)
            if bound:
                path.unlink(missing_ok=True)


def logs(state):
    paths = [state / "services-supervisor.log"]
    directory = state / "services"
    paths.extend([directory / "broker.log", directory / "signer.log", directory / "model-relay.log", directory / "bundler.log",
                  *[directory / f"{name}{suffix}.log" for name in WORKERS for suffix in ("", "-store")]])
    for path in paths:
        if path.exists() or path.is_symlink():
            with os.fdopen(local_state.open_private(path)) as source:
                source.seek(0, os.SEEK_END)
                source.seek(max(0, source.tell() - 16000))
                print(source.read(), end="")
    return 0
