import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from terrier_local import chain, local_state, manager, stack


class Terminal(io.StringIO):
    def isatty(self):
        return True


class StackTests(unittest.TestCase):
    def test_failure_stops_only_a_chain_started_by_this_operation(self):
        for already_running in (False, True):
            with self.subTest(already_running=already_running), mock.patch.object(chain, "status", return_value={"running": already_running}), \
                    mock.patch.object(chain, "start"), mock.patch.object(chain, "stop") as stop_chain, \
                    mock.patch.object(stack.services, "status", return_value={"running": False}), \
                    mock.patch.object(stack.deployment, "deploy", side_effect=ValueError("synthetic invalid deployment")), \
                    mock.patch.object(stack.services, "start") as start_services:
                result = stack.start(Path("."), Path("."))
                self.assertFalse(result["success"])
                self.assertEqual(result["failed_stage"], "deployment")
                self.assertEqual(stop_chain.call_count, 0 if already_running else 1)
                start_services.assert_not_called()

    def test_uncertain_service_state_preserves_chain_and_reports_cleanup_error(self):
        with mock.patch.object(chain, "status", return_value={"running": False}), \
                mock.patch.object(chain, "start"), mock.patch.object(chain, "stop") as stop_chain, \
                mock.patch.object(stack.services, "status", side_effect=[{"running": False}, RuntimeError("control unavailable"), {"running": None}]), \
                mock.patch.object(stack.deployment, "deploy", side_effect=RuntimeError("deployment refused")):
            result = stack.start(Path("."), Path("."))
            self.assertFalse(result["success"])
            self.assertEqual(result["cleanup"]["error"], "control unavailable")
            stop_chain.assert_not_called()

    def test_stop_requires_service_confirmation_before_stopping_chain(self):
        for response in ({"running": True}, {}, {"running": None}):
            with mock.patch.object(stack.services, "stop", return_value=response), \
                    mock.patch.object(chain, "stop") as stop_chain:
                with self.assertRaisesRegex(RuntimeError, "did not confirm"):
                    stack.stop(Path("."))
                stop_chain.assert_not_called()

    def test_partial_status_is_not_healthy_and_reports_both_controllers(self):
        with mock.patch.object(chain, "status", side_effect=RuntimeError("identity changed")), \
                mock.patch.object(stack.services, "status", return_value={"running": True, "ready": True}):
            result = stack.execute(Path("."), Path("."), "doctor")
            self.assertFalse(result["success"])
            self.assertFalse(result["ready"])
            self.assertEqual(result["chain"]["error"], "identity changed")
            self.assertTrue(result["services"]["running"])

    def test_chain_restart_uses_saved_local_profile_without_a_second_port_setting(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            local_state.write_json(state / "chain-profile.json", {"rpc": {"http": "http://127.0.0.1:12345"}})
            with mock.patch.object(chain, "default_profile", return_value={"rpc": {"http": "http://127.0.0.1:8545"}}), \
                    mock.patch.object(chain, "status", side_effect=[{"running": False}, {"running": True}]), \
                    mock.patch.object(chain.contracts, "foundry_binary", return_value="anvil"), \
                    mock.patch.object(chain.subprocess, "Popen") as spawn:
                chain.start(state, state)
                arguments = spawn.call_args.args[0]
                self.assertEqual(arguments[arguments.index("--port") + 1], "12345")
            local_state.write_json(state / "chain-profile.json", {"rpc": {"http": "https://unrelated.example:443"}})
            with mock.patch.object(chain, "default_profile", return_value={}), mock.patch.object(chain.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(ValueError, "loopback"):
                    chain.start(state, state)
                spawn.assert_not_called()

    def test_manager_dispatches_only_canonical_commands_and_surfaces_failures(self):
        output = Terminal()
        dispatch = mock.Mock(side_effect=[1, 0])
        self.assertEqual(manager.run(dispatch, Terminal("wrong\n2\n6\nq\n"), output), 0)
        self.assertEqual(dispatch.call_args_list, [mock.call(["stack", "doctor"]), mock.call(["stack", "stop"])])
        self.assertIn("did not complete", output.getvalue())
        with self.assertRaisesRegex(ValueError, "requires a terminal"):
            manager.run(dispatch, io.StringIO("3\n"), output)
        self.assertEqual(dispatch.call_count, 2)

    def test_manager_reset_requires_the_selected_state_before_cli_dispatch(self):
        state = Path("/synthetic/local-state")
        output = Terminal()
        dispatch = mock.Mock(return_value=0)
        manager.run(dispatch, Terminal(f"7\nwrong\n7\n{state}\nq\n"), output, state=state)
        dispatch.assert_called_once_with(["stack", "reset", "--confirm-state", str(state)])
        self.assertIn("Reset cancelled", output.getvalue())
