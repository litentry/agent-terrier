"""Explicit credential worker qualification against real local contracts."""
import unittest

from qualify_local_storage import LocalStorageFixture


class LocalCredentialTests(LocalStorageFixture):
    def test_owner_and_delegated_credentials_with_real_authority(self):
        self.qualify("agentkeys-worker-creds", "local_storage", "real_chain_credential_worker", "example", "credentials.db")


if __name__ == "__main__":
    unittest.main()
