"""Explicit real-contract and Docker qualification of protected agent commands."""
import json
import base64
import os
from pathlib import Path
import shutil
import sqlite3
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from qualify_local_chain import REPOSITORY, available_port
from qualify_local_login import request
from qualify_local_owner import LocalOwnerFixture
import qualify_local_services
from terrier_local import chain, contracts, local_state, models


class LocalAgentQualification(LocalOwnerFixture):
    def services(self, state, *arguments, **options):
        result = qualify_local_services.LocalServicesQualification.services(self, state, *arguments, **options)
        if os.environ.get("AGENT_TERRIER_TEST_MODEL_DIR") and options.get("success", True):
            if arguments[0] == "stop":
                address = models.endpoint(models.recipe(REPOSITORY)).removeprefix("http://")
                host, port = address.split(":")
                with socket.socket() as listener:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind((host, int(port)))
            elif arguments[0] == "start":
                self.assertTrue(result["services"]["model_runner"]["healthy"])
                self.assertEqual(result["model_runner"]["directory"], os.environ["AGENT_TERRIER_TEST_MODEL_DIR"])
        return result

    def test_create_archive_and_protected_session_denials(self):
        image = os.environ.get("AGENT_TERRIER_TEST_AGENT_IMAGE")
        docker_socket = os.environ.get("AGENT_TERRIER_TEST_DOCKER_SOCKET")
        self.assertTrue(image and docker_socket, "Select an existing reviewed image and explicit Docker socket")
        root = Path(tempfile.mkdtemp(prefix="terrier-agent-", dir="/tmp")).resolve()
        state = root / "state"
        namespace = None
        completed = False
        secrets = []
        qualify_model = os.environ.get("AGENT_TERRIER_TEST_MODEL_CHAT") == "1"
        conversation_marker = "terrier" + uuid.uuid4().hex[:8]
        image_identity = None

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

        def tool_sessions():
            collected = []
            program = r"""
const fs = require('node:fs'); const path = require('node:path'); const sessions = [];
function visit(directory) {
  if (!fs.existsSync(directory)) return;
  for (const entry of fs.readdirSync(directory, {withFileTypes:true})) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) visit(file);
    else if (entry.isFile() && entry.name.endsWith('.jsonl')) {
      sessions.push(fs.readFileSync(file,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)
        .filter(row => row.type === 'tool/call' || row.type === 'tool/result'));
    }
  }
}
visit(process.argv[1]); process.stdout.write(JSON.stringify(sessions));
"""
            for container_id in owned("container"):
                metadata = json.loads(docker("inspect", container_id))[0]
                session_root = str(Path(metadata["Mounts"][0]["Destination"]) / "runtime/sessions")
                collected.extend(json.loads(docker("exec", container_id, "node", "-e", program, session_root)))
            return collected

        try:
            node = self.invoke(state, "start", "--port", str(available_port()))
            self.invoke(state, "deploy", "--offline")
            model_options = []
            if os.environ.get("AGENT_TERRIER_TEST_MODEL_DIR"):
                model_options = ["--model-dir", os.environ["AGENT_TERRIER_TEST_MODEL_DIR"],
                                 "--model-binary", os.environ["AGENT_TERRIER_TEST_MODEL_BINARY"]]
            disk_policy = {"state_limit_mib":1024, "min_free_mib":1024, "check_interval_seconds":2}
            running = self.services(state, "start", "--runtime-image", image, "--docker-socket", docker_socket,
                "--runtime-disk-policy", json.dumps(disk_policy), *model_options)
            self.assertEqual(running["runtime"]["disk_policy"], disk_policy)
            self.assertEqual(local_state.read_json(state / "services/manifest.json")["runtime"]["disk_policy"], disk_policy)
            if model_options:
                capabilities = models.run(REPOSITORY, "probe")
                self.assertEqual(capabilities["embedding_dimensions"], models.recipe(REPOSITORY)["embedding"]["dimension"])

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

            def command(action, *arguments, name="alice", denial=None, incomplete=False):
                result = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "agent", action,
                    "--name", name, *arguments], env=environment, capture_output=True, text=True, timeout=150)
                self.assertTrue(all(secret not in result.stdout + result.stderr for secret in secrets),
                    "agent CLI output exposed protected material")
                if denial:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(denial, result.stderr)
                    self.assertFalse(result.stdout.strip(), "pre-submission denial returned a receipt")
                    return None
                if incomplete:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("operation is incomplete", result.stderr)
                    receipt = json.loads(result.stdout)
                    self.assertTrue(receipt["chain_confirmed"])
                    self.assertFalse(receipt["complete"])
                    return receipt
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
            self.assertEqual(len(created["actor_omni"]), 66)
            def bridge(path, method="GET", body=None, name="alice", denial=None, timeout=30):
                arguments = [sys.executable, str(REPOSITORY / "terrier"), "agent", "bridge", "--name", name,
                    "--device-key-hash", device, "--path", path, "--method", method]
                if body is not None:
                    arguments.append("--json-stdin")
                result = subprocess.run(arguments, input=json.dumps(body) if body is not None else None,
                    env=environment, capture_output=True, text=True, timeout=timeout)
                self.assertTrue(all(secret not in result.stdout + result.stderr for secret in secrets))
                if denial:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(denial, result.stderr)
                    self.assertFalse(result.stdout)
                    return None
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)["response"]

            before = snapshot()
            bridge("/v1/jobs", name="bob", denial="HTTP 409")
            bridge("/v1/sandbox/mgmt/session/export", denial="HTTP 400")
            self.assertEqual(snapshot(), before, "denied bridge call changed chain, relay or runtime")
            self.assertEqual(bridge("/v1/jobs"), {"jobs": []})
            jobs = [{"id": "synthetic-cli-job"}]
            self.assertEqual(bridge("/v1/jobs", "POST", {"jobs": jobs})["jobs"], jobs)
            self.assertEqual(bridge("/v1/jobs")["jobs"], jobs)
            bridge("/v1/jobs", "POST", {"jobs": []})
            if qualify_model:
                relay_key = next(row for row in local_state.read_json(registry)["keys"] if row["key_id"] == device)
                secrets.append(relay_key["key"])
                relay = running["services"]["model_relay"]["url"]
                original_usage = request(relay + "/v1/usage", bearer=relay_key["key"])
                bridge("/v1/chat", "POST", {"text": "must not run", "stream": False}, name="bob", denial="HTTP 409")
                self.assertEqual(request(relay + "/v1/usage", bearer=relay_key["key"]), original_usage,
                    "denied foreign chat consumed model usage")
                reply = bridge("/v1/chat", "POST", {"text": f"The test word for this conversation is {conversation_marker}. Reply directly with exactly that word, without calling tools. /no_think", "stream": False}, timeout=210)
                self.assertIn(conversation_marker, reply.get("reply", ""), "real local model did not return the supplied conversation word")
                self.assertNotEqual(request(relay + "/v1/usage", bearer=relay_key["key"]), original_usage,
                    "authorized model chat did not record relay usage")
            if qualify_model:
                def channel_events(channel):
                    result = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "channel", "poll",
                        channel, "--name", "alice"], env=environment, capture_output=True, text=True, timeout=45)
                    self.assertTrue(all(secret not in result.stdout + result.stderr for secret in secrets))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return json.loads(result.stdout)["response"]["events"]

                def publish_evidence(marker, slot):
                    evidence = []
                    for events in tool_sessions():
                        for event in events:
                            if event["type"] != "tool/call" or event["data"]["name"] != "publish_to_slot":
                                continue
                            arguments = json.loads(event["data"]["arguments"])
                            if arguments.get("body") != marker or arguments.get("slot") != slot:
                                continue
                            result = next((row for row in events if row["type"] == "tool/result" and
                                event["seq"] in row.get("sourceEventSeqs", [])), None)
                            blocks = result["data"]["message"]["content"] if result else []
                            message = next((block for block in blocks if block["type"] == "tool-result" and
                                block["toolCallId"] == event["data"]["callId"]), {})
                            text = json.dumps(message.get("content", []))
                            evidence.append({"completed": bool(message), "failed": message.get("isError") is True,
                                "published": "published:" in text, "authorityDenied": "403" in text})
                    return evidence

                def model_publish(slot, marker):
                    bridge("/v1/chat", "POST", {"text":
                        f'Call publish_to_slot exactly once with slot="{slot}", kind="text", body="{marker}". '
                        'Use the actual tool now; do not just describe the call. Report its result without retrying. /no_think',
                        "stream": False, "session": {"window": "event", "scope": "qualification:" + marker}}, timeout=210)
                    evidence = publish_evidence(marker, slot)
                    self.assertEqual(len(evidence), 1, "model must execute exactly one matching publish tool call")
                    self.assertTrue(evidence[0]["completed"], "tool result was not durably recorded")
                    return evidence[0]

                allowed_marker = "allowed-" + uuid.uuid4().hex
                allowed = model_publish("opchat", allowed_marker)
                self.assertFalse(allowed["failed"], "authorized model tool failed: " + json.dumps(allowed))
                self.assertTrue(allowed["published"], "authorized tool did not return its publish receipt")
                events = channel_events("opchat-local-agent")
                self.assertTrue(any(event["direction"] == "out" and
                    base64.b64decode(event.get("body") or "").decode() == allowed_marker for event in events),
                    "successful tool did not deliver the exact message")
                denied_channel = "ungranted-qualification"
                before_denied = channel_events(denied_channel)
                denied_marker = "denied-" + uuid.uuid4().hex
                denied = model_publish(denied_channel, denied_marker)
                self.assertTrue(denied["failed"] and denied["authorityDenied"],
                    "ungranted tool must fail with an actual authority denial")
                self.assertFalse(denied["published"])
                self.assertEqual(channel_events(denied_channel), before_denied,
                    "denied tool changed the ungranted channel")
                base_grants = ["--service", "channel-pub:opchat-local-agent",
                    "--service", "channel-sub:opchat-local-agent"]
                self.owner(state, "grant", "--name", "alice", "--actor-omni", created["actor_omni"],
                    *base_grants, "--service", "channel-pub:" + denied_channel)
                granted_marker = "granted-" + uuid.uuid4().hex
                granted = model_publish(denied_channel, granted_marker)
                self.assertTrue(granted["published"] and not granted["failed"],
                    "the same tool target must succeed after its real chain grant")
                granted_events = channel_events(denied_channel)
                self.assertEqual(len(granted_events), len(before_denied) + 1)
                self.assertEqual(base64.b64decode(granted_events[-1]["body"]).decode(), granted_marker)
                self.owner(state, "grant", "--name", "alice", "--actor-omni", created["actor_omni"], *base_grants)
                revoked = model_publish(denied_channel, "revoked-" + uuid.uuid4().hex)
                self.assertTrue(revoked["failed"] and revoked["authorityDenied"],
                    "removing the real chain grant must deny the previously permitted tool target")
                self.assertEqual(channel_events(denied_channel), granted_events,
                    "revoked tool changed the channel")
                channel_marker = "channel" + uuid.uuid4().hex[:8]
                published = subprocess.run([sys.executable, str(REPOSITORY / "terrier"), "channel", "publish",
                    "opchat-local-agent", "--name", "alice", "--text-stdin"], env=environment,
                    input=f"Reply with exactly this word: {channel_marker}. /no_think", capture_output=True,
                    text=True, timeout=45)
                self.assertTrue(all(secret not in published.stdout + published.stderr for secret in secrets))
                self.assertEqual(published.returncode, 0, published.stderr)
                self.assertTrue(json.loads(published.stdout)["response"]["ok"])
                deadline = time.monotonic() + 60
                while True:
                    delivered = [event for event in channel_events("opchat-local-agent")
                        if event["direction"] == "out" and not event.get("partial") and
                        channel_marker in base64.b64decode(event.get("body") or "").decode()]
                    if delivered:
                        break
                    self.assertLess(time.monotonic(), deadline, "owner channel message received no completed agent reply")
                    time.sleep(0.5)
            operation_path = state / "owners/alice/operations" / (created["user_op_hash"] + ".json")
            operation = local_state.read_json(operation_path)
            self.assertEqual(operation_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(operation["build"]["user_op"]["signature"], "0x")
            self.assertTrue(all(secret not in operation_path.read_text() for secret in secrets))
            before = snapshot()
            passkey_path = state / "owners/alice/passkey.pem"
            passkey = passkey_path.read_bytes()
            passkey_path.unlink()
            recovered = command("receipt", "--user-op-hash", created["user_op_hash"])
            self.assertEqual(recovered, created)
            self.assertFalse(passkey_path.exists(), "receipt recovery regenerated a signing key")
            local_state.write_private(passkey_path, passkey)
            for field, value, denial in [
                ("development_only", False, "development record"),
                ("operator_omni", bob_session["session"]["omni_account"], "another owner"),
                ("broker_url", "http://127.0.0.1:1", "another broker"),
                ("request_device_key_hash", "0x" + "00" * 32, "another request key"),
            ]:
                local_state.write_json(operation_path, dict(operation, **{field: value}))
                command("receipt", "--user-op-hash", created["user_op_hash"], denial=denial)
                self.assertTrue(snapshot() == before, "denied recovery changed chain, relay or runtime")
            local_state.write_json(operation_path, operation)
            operation_path.chmod(0o644)
            command("receipt", "--user-op-hash", created["user_op_hash"], denial="owner-only")
            operation_path.chmod(0o600)
            foreign_directory = local_state.private_directory(state / "owners/bob/operations")
            local_state.write_json(foreign_directory / operation_path.name, operation)
            command("receipt", "--user-op-hash", created["user_op_hash"], name="bob", denial="another owner")
            forged_binding = dict(operation,
                operator_omni="0x" + bob_session["session"]["omni_account"].removeprefix("0x"),
                request_device_key_hash=bob_session["device_key_hash"])
            local_state.write_json(foreign_directory / operation_path.name, forged_binding)
            command("receipt", "--user-op-hash", created["user_op_hash"], name="bob", denial="HTTP 403")
            self.assertTrue(snapshot() == before, "receipt recovery changed confirmed transaction or runtime")
            containers = owned("container")
            self.assertEqual(len(containers), 1)
            container = json.loads(docker("inspect", containers[0]))[0]
            image_identity = container["Image"]
            self.assertEqual(container["HostConfig"]["NetworkMode"], "none")
            self.assertTrue(all(secret not in json.dumps(container["Config"]["Env"]) for secret in secrets),
                "Docker metadata exposed owner credentials")
            self.assertFalse(any(value.startswith("AGENTKEYS_DEVICE_KEY_HEX=")
                for value in container["Config"]["Env"]), "broker injected a delegate private key")
            context_database = state / "services/broker/spawn_contexts.sqlite"
            with sqlite3.connect(context_database.as_uri() + "?mode=ro", uri=True) as database:
                columns = [row[1] for row in database.execute("PRAGMA table_info(spawn_contexts)")]
                self.assertIn("k10_address", columns)
                self.assertNotIn("k10_secret_hex", columns)
                self.assertEqual(database.execute("SELECT count(*) FROM spawn_contexts").fetchone()[0], 1)
            with sqlite3.connect(context_database) as database:
                stored_address = database.execute("SELECT k10_address FROM spawn_contexts").fetchone()[0]
                database.execute("UPDATE spawn_contexts SET k10_address = ''")
            self.services(state, "stop")
            running = self.services(state, "start")
            self.assertEqual(running["services"]["broker"]["url"], broker)
            before = snapshot()
            invalid_context = command("receipt", "--user-op-hash", created["user_op_hash"], incomplete=True)
            self.assertFalse(invalid_context["runtime_ready"])
            self.assertEqual(snapshot(), before, "invalid context recovery changed chain, relay or runtime")
            with sqlite3.connect(context_database) as database:
                database.execute("UPDATE spawn_contexts SET k10_address = ?", (stored_address,))
            resumed = command("receipt", "--user-op-hash", created["user_op_hash"])
            self.assertTrue(resumed["runtime_ready"])
            self.assertEqual(chain.rpc(node["rpc_http"], "eth_blockNumber"), before[0], "recovery submitted a chain transaction")
            containers = owned("container")
            self.assertEqual(len(containers), 1)
            container = json.loads(docker("inspect", containers[0]))[0]
            if qualify_model:
                reply = bridge("/v1/chat", "POST", {"text": "What is the test word from the first message? Reply with exactly that word. /no_think", "stream": False}, timeout=210)
                self.assertIn(conversation_marker, reply.get("reply", ""), "recreated agent lost its model conversation")
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
            before = snapshot()
            self.assertEqual(command("receipt", "--user-op-hash", archived["user_op_hash"]), archived)
            self.assertTrue(snapshot() == before, "archive receipt recovery resubmitted an operation")
            with os.fdopen(local_state.open_private(state / "services/relay/admin.key")) as source:
                admin_token = source.read().strip()
            secrets.append(admin_token)
            status, response = request(relay + "/v1/admin/keys", {
                "key_id": device, "user_omni": session["session"]["omni_account"],
                "delegate_omni": created["actor_omni"], "device_id": device, "label": "cleanup-retry",
            }, admin_token)
            self.assertEqual(status, 200)
            leftover_key = json.loads(response)["secret"]
            secrets.append(leftover_key)
            self.assertEqual(request(relay + "/v1/usage", bearer=leftover_key)[0], 200)
            self.services(state, "stop")
            restarted = self.services(state, "start")
            relay = restarted["services"]["model_relay"]["url"]
            before = snapshot()
            archive_path = state / "owners/alice/operations" / (archived["user_op_hash"] + ".json")
            archive_record = local_state.read_json(archive_path)
            forged_archive = dict(archive_record,
                operator_omni=forged_binding["operator_omni"], request_device_key_hash=bob_session["device_key_hash"])
            local_state.write_json(foreign_directory / archive_path.name, forged_archive)
            command("receipt", "--user-op-hash", archived["user_op_hash"], name="bob", denial="HTTP 403")
            self.assertTrue(snapshot() == before, "foreign recovery changed a live relay credential")
            self.assertEqual(request(relay + "/v1/usage", bearer=leftover_key)[0], 200)
            restored = command("receipt", "--user-op-hash", archived["user_op_hash"])
            self.assertEqual(restored["user_op_hash"], archived["user_op_hash"])
            self.assertEqual(chain.rpc(node["rpc_http"], "eth_blockNumber"), before[0])
            self.assertEqual(owned("container"), [])
            self.assertEqual(request(relay + "/v1/usage", bearer=leftover_key)[0], 401)
            before = snapshot()
            self.assertEqual(command("receipt", "--user-op-hash", archived["user_op_hash"]), restored)
            self.assertTrue(snapshot() == before, "repeated cleanup changed already-revoked state")
            older_record = dict(archive_record)
            older_record.pop("resources_kept")
            local_state.write_json(archive_path, older_record)
            command("receipt", "--user-op-hash", archived["user_op_hash"], incomplete=True)
            local_state.write_json(archive_path, archive_record)
            retained = docker("run", "--rm", "--pull=never", "--network=none", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=1000:1000",
                "--label", "org.agent-terrier.runtime=" + namespace,
                "--mount", "type=volume,src=" + volume + ",dst=/state,readonly", "--entrypoint", "node", image,
                "-e", "process.stdout.write(require('node:fs').readFileSync('/state/qualification-marker'))")
            self.assertEqual(retained, "synthetic-retained-state")
            if qualify_model:
                print(json.dumps({"qualification": "local-agent-application", "real_chain": True,
                    "protected_owner_login": True, "signer_custody": True, "managed_docker": True,
                    "image_id": image_identity, "container_network": "none", "real_model_chat": True,
                    "restart_recall": True, "foreign_chat_denied": True, "denied_chat_usage_unchanged": True,
                    "revocation": True, "retained_data": True, "model_runner_supervised": bool(model_options),
                    "model_runner_restart_verified": bool(model_options),
                    "model_publish_tool": True, "ungranted_tool_denied": True, "chain_grant_enables_tool": True,
                    "chain_scope_removal_denies_tool": True, "denied_tool_channel_unchanged": True,
                    "owner_channel_to_agent_reply": True,
                    "not_qualified": ["authorized persistent memory retrieval", "browser", "independent clean install"]}))
            completed = True
        finally:
            if not completed:
                try:
                    local_state.write_json(root / "runtime-tool-diagnostics.json", tool_sessions())
                except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired):
                    print("Could not capture private tool diagnostics", file=sys.stderr)
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
