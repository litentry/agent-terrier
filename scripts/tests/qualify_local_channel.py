"""Explicit channel worker qualification against real local contracts."""
import unittest
from qualify_local_storage import LocalStorageFixture


class LocalChannelTests(LocalStorageFixture):
    def test_channel_messages_with_real_authority(self):
        self.qualify("agentkeys-worker-creds", "local_storage", "real_chain_channel_worker", "channel-sub:chat", "channel.db", "agentkeys-worker-channel")


if __name__ == "__main__":
    unittest.main()
