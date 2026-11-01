"""Explicit classifier qualification using the shared real-chain authority fixture."""
import unittest
from qualify_local_storage import LocalStorageFixture


class LocalClassifyTests(LocalStorageFixture):
    def test_classifier_with_real_authority(self):
        self.qualify("agentkeys-worker-creds", "local_storage", "real_chain_classifier_worker",
                     "classify:credentials", None, "agentkeys-worker-classify")


if __name__ == "__main__":
    unittest.main()
