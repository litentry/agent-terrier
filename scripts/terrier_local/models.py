import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import urllib.request
from urllib.parse import urlsplit

from . import chain, contracts, local_state, owner


def run(repository, action, base_url=None, chat_model=None, embedding_model=None):
    if action == "config" and any((base_url, chat_model, embedding_model)):
        raise ValueError("Model configuration display does not accept probe overrides")
    arguments = [str(owner.executable(repository)), "models", action]
    for flag, value in [("--base-url", base_url), ("--chat-model", chat_model),
                        ("--embedding-model", embedding_model)]:
        if value:
            arguments.extend([flag, value])
    result = subprocess.run(arguments, env=contracts.tool_environment(),
                            capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout)


RUNNER_START_TIMEOUT = 60
RESPONSE_LIMIT = 1024 * 1024


def recipe(repository):
    compiled = run(repository, "config")
    if compiled != json.loads((repository / "presets/local-models.json").read_text()):
        raise ValueError("Rebuild the CLI: its model recipe differs from the checked-in source")
    return compiled


def endpoint(configuration):
    parsed = urlsplit(configuration["base_url"])
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.path != "/v1" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Model recipe requires an explicit loopback HTTP endpoint")
    return "http://" + parsed.netloc


def configuration(manifest, directory=None, binary=None):
    previous = manifest.get("model_runner")
    if manifest.get("version", 0) >= 6 and manifest.get("initialized") and "model_runner" not in manifest:
        raise ValueError("Existing model runner configuration is missing; restore the service manifest")
    if previous is not None:
        validate_configuration(previous)
    if directory is None:
        if binary is not None:
            raise ValueError("--model-binary requires --model-dir")
        return previous
    selected_binary = shutil.which(str(binary or "ollama"), path=contracts.tool_environment().get("PATH"))
    if not selected_binary:
        raise ValueError("Install the recipe's Ollama executable or select --model-binary")
    configured = {"directory":str(Path(directory).expanduser().resolve(strict=True)),
                  "binary":str(Path(selected_binary).resolve(strict=True))}
    validate_configuration(configured)
    return configured


def validate_configuration(configured):
    if not isinstance(configured, dict) or set(configured) != {"directory", "binary"}:
        raise ValueError("Invalid persisted model runner configuration")
    for name in ("directory", "binary"):
        value = configured[name]
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError("Model paths must be explicit absolute local paths")
        path = Path(value)
        metadata = path.lstat()
        expected = stat.S_ISDIR if name == "directory" else stat.S_ISREG
        if not expected(metadata.st_mode) or metadata.st_mode & 0o022:
            raise ValueError("Model runner paths must be real files/directories and not writable by other users")
        if name == "binary" and not os.access(path, os.X_OK):
            raise ValueError("Model runner binary is not executable")


def runner_environment(configuration, model_directory, runtime_home, address):
    local_state.private_directory(runtime_home)
    environment = {key:value for key,value in contracts.tool_environment().items()
                   if key in ("PATH", "TMPDIR", "LANG", "LC_ALL")}
    runtime = configuration["runtime"]
    environment.update(HOME=str(runtime_home), OLLAMA_HOST=address.removeprefix("http://"),
        OLLAMA_MODELS=str(model_directory), OLLAMA_NO_CLOUD="1", OLLAMA_NOPRUNE="1",
        OLLAMA_CONTEXT_LENGTH=str(runtime["context_length"]),
        OLLAMA_NUM_PARALLEL=str(runtime["parallel_requests"]),
        OLLAMA_MAX_LOADED_MODELS=str(runtime["max_loaded_models"]))
    return environment


def request(address, route):
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), chain.NoRedirect())
    with client.open(address + route, timeout=2) as response:
        payload = response.read(RESPONSE_LIMIT + 1)
        if len(payload) > RESPONSE_LIMIT:
            raise ValueError("Model runner response exceeds its size bound")
        result = json.loads(payload)
        if not isinstance(result, dict):
            raise ValueError("Model runner returned an invalid response")
        return result


def verify_runner(configuration, address):
    if request(address, "/api/version").get("version") != configuration["runtime"]["version"]:
        raise ValueError("Model runner version differs from the pinned recipe")
    available = request(address, "/api/tags").get("models")
    if not isinstance(available, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in available):
        raise ValueError("Model runner returned an invalid inventory")
    installed = {item.get("name"):item for item in available}
    for selection in (configuration["chat"], configuration["embedding"]):
        if installed.get(selection["model"], {}).get("digest") != selection["digest"]:
            raise ValueError("Missing or changed model; download and verify the pinned recipe first")
    return installed


def wait_ready(process, configuration, address):
    deadline = time.monotonic() + RUNNER_START_TIMEOUT
    while True:
        if process.poll() is not None:
            raise RuntimeError("Owned local model runner exited before becoming ready")
        try:
            installed = verify_runner(configuration, address)
            if process.poll() is not None:
                raise RuntimeError("Owned local model runner exited during readiness verification")
            return installed
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Local model runner startup timed out; inspect services logs") from None
            time.sleep(0.1)


def healthy(configuration, address):
    try:
        verify_runner(configuration, address)
        return True
    except (OSError, ValueError, TypeError):
        return False
