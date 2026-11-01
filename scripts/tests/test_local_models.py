import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import models, services

REPOSITORY = Path(__file__).resolve().parents[2]


class ModelSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.recipe = json.loads((REPOSITORY / "presets/local-models.json").read_text())

    def test_configuration_persists_and_missing_or_unsafe_state_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            binary = Path(sys.executable).resolve()
            configured = models.configuration({"version":5}, directory, binary)
            manifest = {"version":6, "initialized":True, "model_runner":configured}
            self.assertEqual(models.configuration(manifest), configured)
            self.assertIsNone(models.configuration({"version":5, "initialized":True}))
            for value in ({"version":6, "initialized":True}, {"model_runner":{}},
                          {"model_runner":dict(configured, binary="relative")},
                          {"model_runner":dict(configured, directory=str(directory / "missing"))}):
                with self.assertRaises((ValueError, OSError)):
                    models.configuration(value)
            directory.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "not writable"):
                models.configuration(manifest)
            directory.chmod(0o700)
            link = directory / "linked"
            link.symlink_to(binary)
            with self.assertRaises(ValueError):
                models.configuration({"model_runner":dict(configured, binary=str(link))})
            with self.assertRaisesRegex(ValueError, "requires --model-dir"):
                models.configuration({}, binary=binary)

    def test_runner_environment_is_isolated_and_recipe_owned(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inherited = {"PATH":"/usr/bin", "HOME":"/unrelated", "OLLAMA_HOST":"https://remote.invalid",
                         "HTTPS_PROXY":"https://proxy.invalid", "UNRELATED_CREDENTIAL":"synthetic"}
            with mock.patch.object(models.contracts, "tool_environment", return_value=inherited):
                environment = models.runner_environment(self.recipe, directory / "models", directory / "home", "http://127.0.0.1:12345")
            self.assertEqual(environment["HOME"], str(directory / "home"))
            self.assertEqual(environment["OLLAMA_HOST"], "127.0.0.1:12345")
            self.assertEqual(environment["OLLAMA_NO_CLOUD"], "1")
            self.assertEqual(environment["OLLAMA_NOPRUNE"], "1")
            self.assertEqual(environment["OLLAMA_CONTEXT_LENGTH"], str(self.recipe["runtime"]["context_length"]))
            self.assertNotIn("HTTPS_PROXY", environment)
            self.assertNotIn("UNRELATED_CREDENTIAL", environment)
            self.assertEqual((directory / "home").stat().st_mode & 0o777, 0o700)

    def test_recipe_validation_has_positive_and_wrong_identity_controls(self):
        inventory = {"models":[{"name":self.recipe[key]["model"], "digest":self.recipe[key]["digest"]}
                              for key in ("chat", "embedding")]}
        version = {"version":self.recipe["runtime"]["version"]}
        with mock.patch.object(models, "request", side_effect=[version, inventory]):
            self.assertEqual(len(models.verify_runner(self.recipe, "http://127.0.0.1:12345")), 2)
        changed = copy.deepcopy(inventory)
        changed["models"][0]["digest"] = "unqualified"
        for responses in ([{"version":"unqualified"}], [version, {"models":[]}], [version, changed], [version, {"models":None}]):
            with mock.patch.object(models, "request", side_effect=responses), mock.patch.object(models.subprocess, "Popen") as spawn:
                with self.assertRaises(ValueError):
                    models.verify_runner(self.recipe, "http://127.0.0.1:12345")
                spawn.assert_not_called()
        for url in ("https://127.0.0.1:1/v1", "http://remote.invalid:1/v1", "http://user@127.0.0.1:1/v1", "http://127.0.0.1:1/v1?query=x"):
            with self.assertRaisesRegex(ValueError, "loopback"):
                models.endpoint(dict(self.recipe, base_url=url))

    def test_occupied_port_never_adopts_or_changes_an_existing_runner(self):
        with socket.socket() as listener, tempfile.TemporaryDirectory() as temporary:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            address = listener.getsockname()
            recipe = dict(self.recipe, base_url=f"http://127.0.0.1:{address[1]}/v1")
            children = []
            with mock.patch.object(services.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(ValueError, "port is occupied"):
                    services.launch_model({}, recipe, Path(temporary), children)
                spawn.assert_not_called()
            self.assertEqual(children, [])
            self.assertEqual(list(Path(temporary).iterdir()), [])
            with socket.create_connection(address, timeout=1):
                connection, _ = listener.accept()
                connection.close()

    def test_restart_reuses_a_closed_listener_after_an_active_connection(self):
        with socket.socket() as listener, tempfile.TemporaryDirectory() as temporary:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            address = listener.getsockname()
            with socket.create_connection(address) as client:
                connection, _ = listener.accept()
                connection.close()
                self.assertEqual(client.recv(1), b"")
            listener.close()
            recipe = dict(self.recipe, base_url=f"http://127.0.0.1:{address[1]}/v1")
            children = []
            with mock.patch.object(services.subprocess, "Popen") as spawn, mock.patch.object(models, "wait_ready"):
                process, endpoint = services.launch_model({"binary":"fixture", "directory":temporary}, recipe, Path(temporary), children)
                self.assertEqual(process, spawn.return_value)
                self.assertEqual(endpoint, f"http://127.0.0.1:{address[1]}")
                self.assertEqual(children, [spawn.return_value])

    def test_failed_runner_is_cleaned_and_unrelated_process_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "refuse-runner"
            binary.write_text("#!/bin/sh\nexit 7\n")
            binary.chmod(0o700)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            recipe = dict(self.recipe, base_url=f"http://127.0.0.1:{port}/v1")
            unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True)
            children = []
            try:
                with self.assertRaisesRegex(RuntimeError, "exited"):
                    services.launch_model({"binary":str(binary), "directory":str(directory)}, recipe, directory, children)
                services.stop_children(children)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
                self.assertIsNone(unrelated.poll())
            finally:
                os.killpg(unrelated.pid, signal.SIGKILL)
                unrelated.wait(timeout=5)
                services.stop_children(children)

    def test_running_model_configuration_cannot_change_without_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            configured = models.configuration({}, directory, Path(sys.executable).resolve())
            current = {"running":True, "ready":True, "broker_port":12345,
                       "service_schema":services.MANIFEST_VERSION, "model_runner":configured}
            with mock.patch.object(services, "status", return_value=current), mock.patch.object(services.subprocess, "Popen") as spawn:
                self.assertEqual(services.start(REPOSITORY, directory, model_directory=directory,
                    model_binary=Path(sys.executable).resolve()), current)
                other = directory / "other"
                other.mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, "Stop local services"):
                    services.start(REPOSITORY, directory, model_directory=other, model_binary=Path(sys.executable).resolve())
                spawn.assert_not_called()
