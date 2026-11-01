import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

from . import chain, contracts, local_state

START_TIMEOUT = 30
RESPONSE_LIMIT = 4096


def configuration(manifest, enabled=None, port=None):
    if manifest.get("version", 0) >= 7 and manifest.get("initialized") and "website" not in manifest:
        raise ValueError("Existing website configuration is missing; restore the service manifest")
    previous = manifest.get("website")
    if previous is not None:
        validate_configuration(previous)
    if port is not None:
        validate_configuration({"port": port})
        if enabled is not True:
            raise ValueError("--web-port requires --website")
    if enabled is not True:
        return previous
    if previous:
        if port is not None and port != previous["port"]:
            raise ValueError("Website port is bound to browser storage; retain it or use separate local state")
        return previous
    if port is None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
    return {"port": port}


def validate_configuration(configuration):
    if (not isinstance(configuration, dict) or set(configuration) != {"port"}
            or type(configuration["port"]) is not int or not 1 <= configuration["port"] <= 65535):
        raise ValueError("Website configuration requires a valid loopback port")


def endpoint(configuration):
    validate_configuration(configuration)
    return f"http://127.0.0.1:{configuration['port']}"


def prepared_application(repository):
    application = repository / "apps/parent-control"
    if any(list(directory.glob(".env*")) for directory in (repository, application)):
        raise ValueError("Managed website refuses local environment files; use the stack configuration")
    build_identity = application / ".next/BUILD_ID"
    if not build_identity.is_file() or build_identity.is_symlink():
        raise ValueError("Build the public console before enabling --website")
    node = shutil.which("node", path=contracts.tool_environment().get("PATH"))
    if not node:
        raise ValueError("Install Node before enabling --website")
    result = subprocess.run([node, "-p", "require.resolve('next/dist/bin/next')"], cwd=application,
        env=contracts.tool_environment(), capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError("Install the public browser workspace dependencies before enabling --website")
    executable = Path(result.stdout.strip()).resolve(strict=True)
    if not executable.is_file() or not any(executable.is_relative_to(directory / "node_modules")
                                           for directory in (repository, application)):
        raise ValueError("Website executable must belong to the prepared public workspace")
    return application, node, executable


def environment(directory, broker, instance):
    home = local_state.private_directory(directory / "website-home")
    selected = {key:value for key,value in contracts.tool_environment().items()
                if key in ("PATH", "TMPDIR", "LANG", "LC_ALL")}
    selected.update(HOME=str(home), NEXT_TELEMETRY_DISABLED="1", NODE_ENV="production",
                    AGENT_TERRIER_WEB_BACKEND="core", AGENT_TERRIER_WEB_BROKER_URL=broker,
                    AGENT_TERRIER_WEB_INSTANCE=instance)
    return selected


def healthy(address, broker, instance):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), chain.NoRedirect())
    try:
        with opener.open(address + "/api/healthz", timeout=1) as response:
            payload = response.read(RESPONSE_LIMIT + 1)
            if len(payload) > RESPONSE_LIMIT:
                return False
            return response.status == 200 and json.loads(payload) == {
                "ready":True, "service":"terrier-console", "instance":instance,
                "backend":{"kind":"core", "url":broker}}
    except (OSError, ValueError, urllib.error.URLError):
        return False


def launch(repository, configuration, broker, directory, children):
    address = endpoint(configuration)
    application, node, executable = prepared_application(repository)
    with socket.socket() as reservation:
        reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            reservation.bind(("127.0.0.1", configuration["port"]))
        except OSError:
            raise ValueError("Website port is occupied; the existing listener was left untouched") from None
    instance = secrets.token_hex(16)
    selected_environment = environment(directory, broker, instance)
    log = local_state.open_private(directory / "website.log", os.O_CREAT | os.O_WRONLY | os.O_APPEND)
    try:
        process = subprocess.Popen([node, str(executable), "start", "--hostname", "127.0.0.1",
            "--port", str(configuration["port"])], cwd=application, env=selected_environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, umask=0o077)
    finally:
        os.close(log)
    children.append(process)
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Local website exited before readiness; inspect services logs")
        if healthy(address, broker, instance):
            return process, address, instance
        time.sleep(0.1)
    raise RuntimeError("Local website startup timed out; inspect services logs")
