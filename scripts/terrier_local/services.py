from contextlib import ExitStack
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

from . import chain, contracts, deployment, local_state, models, website

SOCKET_NAME = "services.sock"
START_TIMEOUT = models.RUNNER_START_TIMEOUT + website.START_TIMEOUT + 45
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
COMPUTE_WORKERS = {"classify": "agentkeys-worker-classify"}
BROKER_BINARY = "agentkeys-broker-server"
STORE_BINARY = "agentkeys-local-store"
SIGNER_BINARY = "agentkeys-local-signer"
RELAY_BINARY = "agentkeys-gate"
BUNDLER_BINARY = "agentkeys-bundler"
BINARIES = (BROKER_BINARY, STORE_BINARY, SIGNER_BINARY, RELAY_BINARY, BUNDLER_BINARY, *WORKERS.values(), *COMPUTE_WORKERS.values())
MANIFEST_VERSION = 9


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


def validate_manifest(manifest, fingerprint):
    if (not isinstance(manifest, dict) or manifest.get("version") not in (1, 2, 3, 4, 5, 6, 7, 8, MANIFEST_VERSION) or manifest.get("development_only") is not True
            or manifest.get("profile_identity") != fingerprint
            or type(manifest.get("initialized")) is not bool
            or type(manifest.get("broker_port")) is not int
            or not 1 <= manifest["broker_port"] <= 65535):
        raise ValueError("Service state belongs to another deployment or has an invalid manifest")


def prepare(repository, state, binaries, port, runtime_image=None, docker_socket=None, model_directory=None, model_binary=None, enable_website=None, web_port=None, runtime_disk_policy=None):
    running_chain, profile, fingerprint = deployment.active_profile(repository, state)
    directory = local_state.private_directory(state / "services")
    manifest_path = directory / "manifest.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        manifest = local_state.read_json(manifest_path)
        validate_manifest(manifest, fingerprint)
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
    runtime = runtime_configuration(manifest, runtime_image, docker_socket, runtime_disk_policy)
    model_runner = models.configuration(manifest, model_directory, model_binary)
    web_configuration = website.configuration(manifest, enable_website, web_port)
    if web_configuration is not None:
        website.prepared_application(repository)
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
    manifest["runtime"] = runtime
    manifest["model_runner"] = model_runner
    manifest["website"] = web_configuration
    manifest["version"] = MANIFEST_VERSION
    manifest["initialized"] = True
    local_state.write_json(manifest_path, manifest)
    return manifest


def runtime_configuration(manifest, image=None, socket_path=None, disk_policy=None):
    if (image is None) != (socket_path is None):
        raise ValueError("Runtime image and Docker socket must be configured together")
    if manifest.get("version", 0) >= 5 and manifest.get("initialized") and "runtime" not in manifest:
        raise ValueError("Existing runtime configuration is missing; restore the service manifest")
    previous = manifest.get("runtime")
    if previous is not None:
        validate_runtime_configuration(previous)
    if disk_policy is not None:
        if not isinstance(disk_policy, str) or len(disk_policy) > 4096:
            raise ValueError("Runtime disk policy must be a JSON object; see the disk-policy reference")
        disk_policy = json.loads(disk_policy)
        if not isinstance(disk_policy, dict):
            raise ValueError("Runtime disk policy must be a JSON object; see the disk-policy reference")
    if image is None:
        if disk_policy is None:
            return previous
        if previous is None:
            raise ValueError("Configure a local runtime image and Docker socket before its disk policy")
        return {**previous, "disk_policy":disk_policy}
    configured = {"image":image, "socket":str(Path(socket_path).expanduser()),
                  "namespace":previous["namespace"] if previous else "terrier-" + secrets.token_hex(16)}
    if disk_policy is not None or previous and "disk_policy" in previous:
        configured["disk_policy"] = disk_policy if disk_policy is not None else previous["disk_policy"]
    validate_runtime_configuration(configured)
    if previous and previous["socket"] != configured["socket"]:
        raise ValueError("Existing runtime state belongs to another Docker socket; use a separate local state directory")
    return configured


def validate_runtime_configuration(configuration):
    if not isinstance(configuration, dict) or set(configuration) not in ({"image", "socket", "namespace"}, {"image", "socket", "namespace", "disk_policy"}):
        raise ValueError("Invalid persisted runtime configuration")
    if "disk_policy" in configuration and (not isinstance(configuration["disk_policy"], dict) or len(json.dumps(configuration["disk_policy"])) > 4096):
        raise ValueError("Invalid persisted runtime disk policy")
    image, endpoint, namespace = (configuration[name] for name in ("image", "socket", "namespace"))
    if (not all(isinstance(value, str) and value for value in (image, endpoint, namespace))
            or image.startswith("-") or any(character.isspace() for character in image)
            or not Path(endpoint).is_absolute() or "://" in endpoint
            or not namespace.startswith("terrier-") or len(namespace) > 48
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in namespace)):
        raise ValueError("Invalid local image, Docker socket or runtime namespace")


def runtime_environment(repository, directory, configuration):
    if configuration is None:
        return {}
    validate_runtime_configuration(configuration)
    client_directory = local_state.private_directory(directory / "docker-client")
    client_config = client_directory / "config.json"
    if client_config.exists() or client_config.is_symlink():
        if local_state.read_json(client_config) != {}:
            raise ValueError("The local runtime Docker client must have an empty isolated configuration")
    else:
        local_state.write_json(client_config, {})
    return {"AGENT_TERRIER_LOCAL_DEV":"1", "AGENT_TERRIER_SANDBOX_IMAGE":configuration["image"],
            "AGENT_TERRIER_DOCKER_SOCKET":configuration["socket"],
            "AGENT_TERRIER_RUNTIME_NAMESPACE":configuration["namespace"],
            "AGENT_TERRIER_TRANSPORT_SCRIPT":str((repository / "packages/agent-terrier-runtime/service-transport.mjs").resolve()),
            "DOCKER_CONFIG":str(client_directory),
            **({"AGENT_TERRIER_RUNTIME_DISK_POLICY":json.dumps(configuration["disk_policy"])} if "disk_policy" in configuration else {})}


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


def start(repository, state, configured=None, port=None, runtime_image=None, docker_socket=None, model_directory=None, model_binary=None, enable_website=None, web_port=None, runtime_disk_policy=None):
    current = status(state)
    if current["running"]:
        if current.get("service_schema") != MANIFEST_VERSION:
            raise RuntimeError("The running services use an older schema; stop and restart them to migrate")
        if not current.get("ready"):
            raise RuntimeError("Local services are unhealthy; inspect doctor/logs, then stop before restarting")
        if port is not None and current["broker_port"] != port:
            raise ValueError("The owned broker is already running on a different port")
        if runtime_image is not None or docker_socket is not None or runtime_disk_policy is not None:
            requested = runtime_configuration({"runtime":current.get("runtime")}, runtime_image, docker_socket, runtime_disk_policy)
            if requested != current.get("runtime"):
                raise ValueError("Stop local services before changing runtime configuration")
        if model_directory is not None or model_binary is not None:
            requested = models.configuration({"model_runner":current.get("model_runner")}, model_directory, model_binary)
            if requested != current.get("model_runner"):
                raise ValueError("Stop local services before changing model runner configuration")
        if enable_website is not None or web_port is not None:
            requested = website.configuration({"website":current.get("website")}, enable_website, web_port)
            if requested != current.get("website"):
                raise ValueError("Stop local services before changing website configuration")
        return current
    binaries = binary_directory(repository, configured)
    prepare(repository, state, binaries, port, runtime_image, docker_socket, model_directory, model_binary, enable_website, web_port, runtime_disk_policy)
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


def signal_child_group(process, selected_signal):
    try:
        os.killpg(process.pid, selected_signal)
    except ProcessLookupError:
        pass


def stop_children(children):
    for process in children:
        signal_child_group(process, signal.SIGTERM)
    deadline = time.monotonic() + STOP_TIMEOUT
    for process in children:
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            signal_child_group(process, signal.SIGKILL)
            process.wait(timeout=2)
        signal_child_group(process, signal.SIGKILL)
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
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log, text=True, start_new_session=True, umask=0o077)
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


def launch_model(configuration, recipe, directory, children):
    address = models.endpoint(recipe)
    host, port = address.removeprefix("http://").split(":")
    with socket.socket() as reservation:
        reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            reservation.bind((host, int(port)))
        except OSError:
            raise ValueError("Model recipe port is occupied; stop that runner explicitly before starting owned services") from None
    environment = models.runner_environment(recipe, configuration["directory"],
        directory / "model-home", address)
    log = local_state.open_private(directory / "model-runner.log", os.O_CREAT | os.O_WRONLY | os.O_APPEND)
    try:
        process = subprocess.Popen([configuration["binary"], "serve"], env=environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, umask=0o077)
    finally:
        os.close(log)
    children.append(process)
    models.wait_ready(process, recipe, address)
    return process, address


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
        reservations = ExitStack()
        reserved_listeners = {}
        children = []
        components = {}
        website_instance = None
        browser_origin = website.endpoint(manifest["website"]) if manifest["website"] is not None else ""
        path = chain.socket_path(state, SOCKET_NAME)
        bound = False

        def interrupted(_signal, _frame):
            raise InterruptedError("Local services supervisor stopped")

        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        try:
            for name in ("broker", "signer", *WORKERS, *COMPUTE_WORKERS):
                listener = reservations.enter_context(socket.socket())
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", manifest["broker_port"] if name == "broker" else 0))
                listener.listen(1)
                reserved_listeners[name] = listener
            endpoints = {name:f"http://127.0.0.1:{listener.getsockname()[1]}" for name, listener in reserved_listeners.items()}

            def launch_reserved(name, binary, arguments, environment):
                address = endpoints[name].removeprefix("http://")
                reserved_listeners[name].close()
                launched = launch(binary, [*arguments, "--listen", address], environment, directory / f"{name}.log", children)
                if launched[1] != endpoints[name]:
                    raise ValueError("Local service listener differs from its reserved endpoint")
                return launched

            model_recipe = models.recipe(repository) if manifest["model_runner"] is not None else None
            if model_recipe is not None:
                components["model_runner"] = launch_model(manifest["model_runner"], model_recipe, directory, children)
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
            environment["BROKER_BROWSER_ORIGINS"] = browser_origin
            environment.update(AGENTKEYS_GATE_ADMIN_URL=components["model_relay"][1],
                AGENTKEYS_GATE_ADMIN_TOKEN_FILE=str(relay_directory / "admin.key"),
                AGENTKEYS_GATE_TURN_URL=components["model_relay"][1] + "/v1", AGENTKEYS_BUNDLER_URL=components["bundler"][1],
                BROKER_SPONSOR_SIGNER_KEY_FILE=str(directory / "bundler/submitter.key"))
            environment.update(AGENTKEYS_DELEGATE_KEYS="signer", AGENTKEYS_SIGNER_URL=endpoints["signer"])
            for name in (*WORKERS, *COMPUTE_WORKERS):
                worker = "cred" if name == "credentials" else name
                environment[f"AGENTKEYS_WORKER_{worker.upper()}_URL"] = endpoints[name]
            environment.update(runtime_environment(repository, directory, manifest["runtime"]))
            reserved_listeners["broker"].close()
            components["broker"] = launch(binaries / BROKER_BINARY,
                broker_arguments(broker_directory, manifest["broker_port"]),
                environment, directory / "broker.log", children)
            if components["broker"][1] != environment["BROKER_OIDC_ISSUER"]:
                raise ValueError("Broker listener differs from the persisted session issuer")
            components["signer"] = launch_reserved("signer", binaries / SIGNER_BINARY,
                ["--development", "--profile", profile_path, "--broker-public-key", public_key,
                 "--master-secret-file", directory / "signer/master.key"],
                contracts.tool_environment())
            for data_class, worker_binary in WORKERS.items():
                worker_directory = directory / data_class
                common = ["--development", "--profile", profile_path, "--broker-public-key", public_key]
                store = launch(binaries / STORE_BINARY,
                    [*common, "--database", worker_directory / "objects.db", "--data-class", data_class],
                    contracts.tool_environment(), directory / f"{data_class}-store.log", children)
                components[data_class + "_store"] = store
                components[data_class] = launch_reserved(data_class, binaries / worker_binary,
                    [*common, "--storage-url", store[1], "--development-kek-file", worker_directory / "development.key",
                     "--browser-origins", browser_origin],
                    contracts.tool_environment())

            for name, worker_binary in COMPUTE_WORKERS.items():
                components[name] = launch_reserved(name, binaries / worker_binary,
                    ["--development", "--profile", profile_path, "--broker-public-key", public_key,
                     "--browser-origins", browser_origin], contracts.tool_environment())

            if manifest["website"] is not None:
                process, address, website_instance = website.launch(repository, manifest["website"],
                    components["broker"][1], directory, children)
                components["website"] = (process, address)

            def snapshot():
                services = {name:{"url":endpoint, "healthy":process.poll() is None and (models.healthy(model_recipe, endpoint) if name == "model_runner"
                                else website.healthy(endpoint, components["broker"][1], website_instance) if name == "website"
                                else healthy(endpoint, name in ("broker", "model_relay")))}
                            for name, (process, endpoint) in components.items()}
                running_chain = chain.status(state)
                profile = local_state.read_json(profile_path)
                profile_matches = (deployment.profile_identity(profile) == manifest["profile_identity"]
                                   and profile.get("rpc", {}).get("http") == running_chain.get("rpc_http")
                                   and profile.get("contract_set_version") ==
                                   (repository / "crates/agentkeys-chain/VERSION").read_text().strip())
                return {"running":True, "service_schema":MANIFEST_VERSION, "ready":running_chain["running"] and profile_matches and all(item["healthy"] for item in services.values()),
                        "development_only":True, "broker_port":manifest["broker_port"], "runtime":manifest["runtime"], "model_runner":manifest["model_runner"], "website":manifest["website"],
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
            reservations.close()
            if bound:
                path.unlink(missing_ok=True)


def logs(state):
    paths = [state / "services-supervisor.log"]
    directory = state / "services"
    paths.extend([directory / "broker.log", directory / "signer.log", directory / "model-relay.log", directory / "model-runner.log", directory / "bundler.log", directory / "website.log",
                  *[directory / f"{name}.log" for name in COMPUTE_WORKERS],
                  *[directory / f"{name}{suffix}.log" for name in WORKERS for suffix in ("", "-store")]])
    for path in paths:
        if path.exists() or path.is_symlink():
            with os.fdopen(local_state.open_private(path)) as source:
                source.seek(0, os.SEEK_END)
                source.seek(max(0, source.tell() - 16000))
                print(source.read(), end="")
    return 0
