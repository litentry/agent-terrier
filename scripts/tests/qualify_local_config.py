"""Explicit configuration worker qualification against real local contracts."""
import unittest
from qualify_local_storage import LocalStorageFixture


class LocalConfigTests(LocalStorageFixture):
    def test_owner_configuration_with_real_authority(self):
        self.qualify("agentkeys-worker-creds", "local_storage", "real_chain_config_worker", "example", "config.db", "agentkeys-worker-config")


if __name__ == "__main__":
    unittest.main()
