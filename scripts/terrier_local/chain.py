import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import contracts, local_state

START_TIMEOUT = 20
STOP_TIMEOUT = 15
RPC_TIMEOUT = 2
MESSAGE_LIMIT = 4096
RESPONSE_LIMIT = 1024 * 1024
SOCKET_NAME = "chain.sock"


def default_profile(repository):
    return json.loads((repository / "crates/agentkeys-core/chain-profiles/anvil.json").read_text())


def rpc(endpoint, method, parameters=None):
    location = urllib.parse.urlsplit(endpoint)
    if (location.scheme != "http" or location.hostname != "127.0.0.1"
            or location.username or location.password or location.query or location.fragment
            or location.path not in ("", "/") or not location.port):
        raise ValueError("Local chain RPC must be an explicit IPv4 loopback HTTP endpoint")
    request = urllib.request.Request(endpoint, data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": parameters or [],
    }).encode(), headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=RPC_TIMEOUT) as response:
            payload = response.read(RESPONSE_LIMIT + 1)
    except (OSError, urllib.error.URLError):
        raise RuntimeError("Local chain RPC is unavailable") from None
    if len(payload) > RESPONSE_LIMIT:
        raise ValueError("Local chain RPC response is too large")
    result = json.loads(payload)
    if not isinstance(result, dict) or result.get("id") != 1 or "error" in result or "result" not in result:
        raise RuntimeError(f"Local chain RPC rejected {method}")
    return result["result"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise ValueError("Local chain RPC redirects are forbidden")


def node_identity(endpoint, chain_id, instance_id=None):
    metadata = rpc(endpoint, "anvil_metadata")
    if (not isinstance(metadata, dict) or metadata.get("chainId") != chain_id
            or not str(metadata.get("clientVersion", "")).startswith("anvil/")
            or metadata.get("forkedNetwork") is not None
            or not isinstance(metadata.get("instanceId"), str)
            or len(metadata["instanceId"]) != 66
            or (instance_id and metadata["instanceId"] != instance_id)):
        raise ValueError("Local chain identity changed or is not an unforked development node")
    if rpc(endpoint, "eth_chainId") != hex(chain_id) or rpc(endpoint, "eth_accounts") != []:
        raise ValueError("Local chain must have the expected ID and no unlocked accounts")
    return metadata["instanceId"]


def socket_path(state):
    path = state / SOCKET_NAME
    if len(os.fsencode(path)) > 100:
        raise ValueError("Local state path is too long for its control socket; choose a shorter state directory")
    return path


def validate_socket(path):
    metadata = path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("Local control socket must be owned by this user with mode 0600")


def receive_message(connection):
    payload = bytearray()
    while b"\n" not in payload and len(payload) <= MESSAGE_LIMIT:
        chunk = connection.recv(min(1024, MESSAGE_LIMIT + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > MESSAGE_LIMIT or not payload.endswith(b"\n"):
        raise ValueError("Invalid local control message")
    result = json.loads(payload)
    if not isinstance(result, dict):
        raise ValueError("Invalid local control message")
    return result


def control(state, action):
    path = socket_path(state)
    try:
        validate_socket(path)
    except FileNotFoundError:
        return {"running": False}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(STOP_TIMEOUT + RPC_TIMEOUT * 3)
        try:
            connection.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            return {"running": False}
        connection.sendall((json.dumps({"action": action}) + "\n").encode())
        result = receive_message(connection)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result


def status(state):
    return control(state, "status")


def start(repository, state, port=None):
    profile = default_profile(repository)
    selected_port = port if port is not None else urllib.parse.urlsplit(profile["rpc"]["http"]).port
    if not isinstance(selected_port, int) or not 1 <= selected_port <= 65535:
        raise ValueError("Chain port must be between 1 and 65535")
    current = status(state)
    if current["running"]:
        if port is not None and urllib.parse.urlsplit(current["rpc_http"]).port != port:
            raise ValueError("The owned chain is already running on a different port")
        return current
    anvil = contracts.foundry_binary("anvil")
    log = local_state.open_private(state / "chain-supervisor.log", os.O_CREAT | os.O_WRONLY | os.O_APPEND)
    environment = contracts.tool_environment()
    environment["AGENT_TERRIER_STATE_DIR"] = str(state)
    try:
        process = subprocess.Popen([
            sys.executable, str(repository / "terrier"), "_serve-chain",
            "--port", str(selected_port), "--anvil", anvil,
        ], stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment, start_new_session=True)
    finally:
        os.close(log)
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        current = status(state)
        if current["running"]:
            return current
        if process.poll() is not None:
            raise RuntimeError("Local chain could not start; inspect terrier chain logs")
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=STOP_TIMEOUT)
    raise RuntimeError("Local chain startup timed out; inspect terrier chain logs")


def stop(state):
    return control(state, "stop")


def serve(repository, state, port, anvil):
    os.umask(0o077)
    with local_state.exclusive_lock(state / "chain.lock"):
        serve_owned(repository, state, port, anvil)
    return 0


def serve_owned(repository, state, port, anvil):
    chain_directory = local_state.private_directory(state / "chain")
    snapshot = chain_directory / "state.json"
    if snapshot.exists() or snapshot.is_symlink():
        os.close(local_state.open_private(snapshot))
    profile = default_profile(repository)
    endpoint = f"http://127.0.0.1:{port}"
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            raise RuntimeError("Chain port is in use; the existing listener was left untouched") from None
    log = local_state.open_private(state / "chain.log", os.O_CREAT | os.O_WRONLY | os.O_APPEND)
    try:
        process = subprocess.Popen([
            anvil, "--host", "127.0.0.1", "--port", str(port), "--chain-id", str(profile["chain_id"]),
            "--accounts", "0", "--no-cors", "--quiet", "--state", str(snapshot),
        ], stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=contracts.tool_environment())
    finally:
        os.close(log)
    path = socket_path(state)
    bound = False

    def interrupted(signum, frame):
        raise InterruptedError("Local supervisor stopped")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        deadline = time.monotonic() + START_TIMEOUT / 2
        while True:
            if process.poll() is not None:
                raise RuntimeError("Local node exited during startup")
            try:
                instance_id = node_identity(endpoint, profile["chain_id"])
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Local node did not become ready") from None
                time.sleep(0.1)
        if path.exists() or path.is_symlink():
            validate_socket(path)
            path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            bound = True
            path.chmod(0o600)
            listener.listen(4)
            listener.settimeout(0.5)
            while process.poll() is None:
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(RPC_TIMEOUT)
                    stopped = False
                    try:
                        request = receive_message(connection)
                        if request.get("action") not in ("status", "stop"):
                            raise ValueError("Unsupported local control action")
                        if request["action"] == "stop":
                            process.terminate()
                            process.wait(timeout=STOP_TIMEOUT)
                            if process.returncode != 0:
                                raise RuntimeError("Local node stopped abnormally; saved state requires inspection")
                            stopped = True
                            result = {"running": False, "state_saved": snapshot.is_file()}
                        else:
                            node_identity(endpoint, profile["chain_id"], instance_id)
                            result = {"running": True, "rpc_http": endpoint, "chain_id": profile["chain_id"],
                                      "instance_id": instance_id, "development_only": True}
                    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                        result = {"error": str(error)}
                    try:
                        connection.sendall((json.dumps(result) + "\n").encode())
                    except OSError:
                        pass
                    if stopped:
                        return
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=STOP_TIMEOUT)
        if bound:
            path.unlink(missing_ok=True)


def logs(state):
    for name in ("chain-supervisor.log", "chain.log", "deployment.log"):
        path = state / name
        if path.exists():
            with os.fdopen(local_state.open_private(path)) as source:
                source.seek(0, os.SEEK_END)
                source.seek(max(0, source.tell() - 16000))
                print(source.read(), end="")
    return 0
