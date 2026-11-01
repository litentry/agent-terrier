"""Explicit real-contract and Docker qualification of protected agent commands."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from qualify_local_chain import REPOSITORY, available_port
from qualify_local_login import request
from qualify_local_owner import LocalOwnerFixture
import qualify_local_services
from terrier_local import chain, contracts, local_state


class LocalAgentQualification(LocalOwnerFixture):
    services = qualify_local_services.LocalServicesQualification.services

    def test_create_archive_and_protected_session_denials(self):
        image = os.environ.get("AGENT_TERRIER_TEST_AGENT_IMAGE")
        docker_socket = os.environ.get("AGENT_TERRIER_TEST_DOCKER_SOCKET")
        self.assertTrue(image and docker_socket, "Select an existing reviewed image and explicit Docker socket")
        root = Path(tempfile.mkdtemp(prefix="terrier-agent-", dir="/tmp")).resolve()
        state = root / "state"
        namespace = None
        completed = False
        secrets = []

        def docker(*arguments):
            environment = contracts.tool_environment()
            environment["DOCKER_CONFIG"] = str(state / "services/docker-client")
            result = subprocess.run(["docker", "--host", "unix://" + docker_socket, *arguments],
                env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, "owned Docker qualification command failed")
            return result.stdout.strip()

        def owned(kind):
            if namespace is None:
                return []
            return docker(kind, "ls", *(["-a"] if kind == "container" else []), "--quiet",
                "--filter", "label=org.agent-terrier.runtime=" + namespace).split()

        try:
            node = self.invoke(state, "start", "--port", str(available_port()))
            self.invoke(state, "deploy", "--offline")
            running = self.services(state, "start", "--runtime-image", image, "--docker-socket", docker_socket)
            namespace = running["runtime"]["namespace"]
            broker = running["services"]["broker"]["url"]
            for name in ("alice", "bob"):
                self.owner(state, "register", "--name", name)
                self.owner(state, "login", "--name", name, "--broker-url", broker)
                directory = state / "owners" / name
                secrets.extend([local_state.read_json(directory / "session.json")["session"]["session_jwt"],
                    (directory / "device.key").read_text().strip(), (directory / "passkey.pem").read_text().strip()])
            session_path = state / "owners/alice/session.json"
            session = local_state.read_json(session_path)
            environment = contracts.tool_environment()
            environment["AGENT_TERRIER_STATE_DIR"] = str(state)
            registry = state / "services/relay/keys.json"

            def command(action, *arguments, name="alice", denial=None):
                result = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "agent", action,
                    "--name", name, *arguments], env=environment, capture_output=True, text=True, timeout=150)
                self.assertTrue(all(secret not in result.stdout + result.stderr for secret in secrets),
                    "agent CLI output exposed protected material")
                if denial:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(denial, result.stderr)
                    self.assertFalse(result.stdout.strip(), "pre-submission denial returned a receipt")
                    return None
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                receipt = json.loads(result.stdout)
                self.assertTrue(receipt["complete"] and receipt["chain_confirmed"])
                return receipt

            def snapshot():
                return chain.rpc(node["rpc_http"], "eth_blockNumber"), registry.read_bytes(), owned("container")

            before = snapshot()
            corrupt_bearer = session["session"]["session_jwt"].rsplit(".", 1)[0] + ".invalid"
            bob_session = local_state.read_json(state / "owners/bob/session.json")
            mutations = [
                (dict(session, development_only=False), "development-only"),
                (dict(session, broker_url="http://127.0.0.1:1"), "another broker"),
                (dict(session, device_key_hash="0x" + "00" * 32), "another request key"),
                (dict(session, session=dict(session["session"], expires_at=0)), "expired"),
                (dict(session, session=dict(session["session"], session_jwt=corrupt_bearer)), "HTTP 401"),
                (bob_session, "another owner"),
                (dict(session, session=dict(session["session"], session_jwt=bob_session["session"]["session_jwt"])), "another owner"),
            ]
            for changed, denial in mutations:
                local_state.write_json(session_path, changed)
                command("spawn", "--label", "refused", denial=denial)
                self.assertTrue(snapshot() == before, "denied creation changed chain, relay or containers")
            local_state.write_json(session_path, session)
            session_path.chmod(0o644)
            command("spawn", "--label", "refused", denial="owner-only")
            session_path.chmod(0o600)
            session_path.unlink()
            session_path.symlink_to(state / "owners/bob/session.json")
            command("spawn", "--label", "refused", denial="protected local session")
            session_path.unlink()
            local_state.write_json(session_path, session)
            key_path = state / "owners/alice/device.key"
            request_key = key_path.read_bytes()
            key_path.unlink()
            command("spawn", "--label", "refused", denial="existing owner request key")
            self.assertFalse(key_path.exists())
            local_state.write_private(key_path, request_key)
            self.assertTrue(snapshot() == before, "unsafe/missing-file denials changed state")

            created = command("spawn", "--label", "local-agent")
            device = created["device_key_hash"]
            containers = owned("container")
            self.assertEqual(len(containers), 1)
            container = json.loads(docker("inspect", containers[0]))[0]
            self.assertEqual(container["HostConfig"]["NetworkMode"], "none")
            self.assertTrue(all(secret not in json.dumps(container["Config"]["Env"]) for secret in secrets),
                "Docker metadata exposed owner credentials")
            mounts = container["Mounts"]
            self.assertEqual(len(mounts), 1)
            self.assertEqual(mounts[0]["Type"], "volume")
            volume = mounts[0]["Name"]
            marker = str(Path(mounts[0]["Destination"]) / "qualification-marker")
            docker("exec", containers[0], "node", "-e",
                "require('node:fs').writeFileSync(process.argv[1], 'synthetic-retained-state')", marker)
            relay_key = next(row for row in local_state.read_json(registry)["keys"] if row["key_id"] == device)
            secrets.append(relay_key["key"])
            relay = running["services"]["model_relay"]["url"]
            self.assertEqual(request(relay + "/v1/usage", bearer=relay_key["key"])[0], 200)
            before = snapshot()
            command("archive", "--device-key-hash", device, name="bob", denial="HTTP 403")
            self.assertTrue(snapshot() == before, "foreign archive changed chain, relay or runtime")
            archived = command("archive", "--device-key-hash", device)
            self.assertTrue(archived["resources_kept"] and archived["context_removed"] and archived["runtime_stopped"])
            self.assertEqual(owned("container"), [])
            self.assertIn(volume, owned("volume"))
            self.assertEqual(request(relay + "/v1/usage", bearer=relay_key["key"])[0], 401)
            retained = docker("run", "--rm", "--pull=never", "--network=none", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=1000:1000",
                "--label", "org.agent-terrier.runtime=" + namespace,
                "--mount", "type=volume,src=" + volume + ",dst=/state,readonly", "--entrypoint", "node", image,
                "-e", "process.stdout.write(require('node:fs').readFileSync('/state/qualification-marker'))")
            self.assertEqual(retained, "synthetic-retained-state")
            completed = True
        finally:
            self.services(state, "stop")
            for container in owned("container"):
                docker("rm", "--force", container)
            for volume in owned("volume"):
                docker("volume", "rm", volume)
            self.invoke(state, "stop")
            if completed:
                shutil.rmtree(root)
            else:
                print("Private qualification diagnostics retained at " + str(root), file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
