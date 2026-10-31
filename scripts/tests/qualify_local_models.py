"""Explicit macOS real-model qualification with outbound networking denied."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import contracts, models, owner

REPOSITORY = Path(__file__).resolve().parents[2]
LOOPBACK_HOST = "127.0.0.1"
TEST_NETWORK_ADDRESS = "192.0.2.1"
OFFLINE_PROFILE = '(version 1) (allow default) (deny network-outbound) (allow network-outbound (remote ip "localhost:*"))'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def qualify(model_directory, binary):
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        raise ValueError("This offline qualification requires macOS sandbox-exec; the model probe itself is portable")
    recipe = models.run(REPOSITORY, "config")
    if recipe != json.loads((REPOSITORY / "presets/local-models.json").read_text()):
        raise ValueError("Rebuild the CLI: its model recipe differs from the checked-in source")
    model_directory = model_directory.expanduser().resolve(strict=True)
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
        with socket.socket() as listener:
            listener.bind((LOOPBACK_HOST,0))
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
                return {
                    "qualification":"local-model-capabilities", "external_network_denied":True,
                    "operating_system":platform.mac_ver()[0], "architecture":platform.machine(),
                    "hardware":subprocess.check_output(["sysctl","-n","machdep.cpu.brand_string"],text=True).strip(),
                    "physical_memory_bytes":int(subprocess.check_output(["sysctl","-n","hw.memsize"],text=True)),
                    "runtime_version":version, "recipe":recipe,
                    "model_bytes":sum(installed[recipe[key]["model"]]["size"] for key in ("chat","embedding")),
                    "runner_startup_seconds":round(startup_seconds,3),
                    "probe_seconds":round(time.monotonic()-probe_started,3),
                    "peak_runner_process_rss_kib":peak_rss[0], "capabilities":json.loads(result.stdout),
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
    arguments = parser.parse_args()
    try:
        if not arguments.ollama:
            raise ValueError("Install the recipe's Ollama version first")
        print(json.dumps(qualify(arguments.models_dir,arguments.ollama),indent=2))
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        print(f"model qualification: {error}",file=sys.stderr)
        raise SystemExit(1)
