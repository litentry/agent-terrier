"""Explicit memory worker qualification against real local contracts."""
import unittest
from qualify_local_storage import LocalStorageFixture


class LocalMemoryTests(LocalStorageFixture):
    def test_canonical_memory_with_real_authority(self):
        self.qualify("agentkeys-worker-creds", "local_storage", "real_chain_memory_worker", "knowledge:notes", "memory.db", "agentkeys-worker-memory")


if __name__ == "__main__":
    unittest.main()
