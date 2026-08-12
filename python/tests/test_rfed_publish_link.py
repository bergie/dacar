"""Test that RFedClient.publish sends directly without establishing a link.

Per the Rust reference implementation (canonical), the rfed.channel.publish
destination does NOT accept link requests - it only accepts direct DATA packets.
This test verifies that the Python client correctly sends packets directly to
the destination rather than trying to establish a link.
"""

import unittest
from unittest.mock import patch, MagicMock
import RNS

from dacar.rfed.client import RFedClient
from dacar.rfed.constants import CHANNEL_PUBLISH_NAME


class TestPublishDirectTransport(unittest.TestCase):
    """Test that RFedClient.publish sends directly without links."""

    def setUp(self):
        """Set up a test client with fake RNS."""
        self.identity = RNS.Identity()
        self.rns = MagicMock()
        self.client = RFedClient(identity=self.identity, rns=self.rns)

    @patch('dacar.rfed.client.RNS.Packet')
    @patch('dacar.rfed.client.wrap_channel_message')
    @patch.object(RFedClient, '_ensure_path')
    @patch.object(RFedClient, '_out_destination')
    @patch.object(RFedClient, '_channel')
    @patch.object(RFedClient, '_node_identity')
    def test_publish_sends_directly_without_link(
        self,
        mock_node_identity,
        mock_channel,
        mock_out_destination,
        mock_ensure_path,
        mock_wrap_channel,
        mock_packet_class,
    ):
        """Publish should ensure path then send packet directly (no link)."""
        # Set up mocks
        node_hash = b'\x00' * 32
        node_identity = self.identity
        mock_node_identity.return_value = node_identity

        channel = {
            'identity': RNS.Identity(),
            'channel_hash': b'\x01' * 16,
        }
        mock_channel.return_value = channel

        dest = MagicMock()
        dest.hash = b'\x02' * 16
        mock_out_destination.return_value = dest

        wrapped = MagicMock()
        wrapped.rfed_payload = b'test_payload'
        mock_wrap_channel.return_value = wrapped

        packet = MagicMock()
        mock_packet_class.return_value = packet

        # Call publish
        lxm_message = MagicMock()
        self.client.publish(node_hash, 'dacar.policy.v1', lxm_message)

        # Verify: NO link creation, direct packet send
        mock_ensure_path.assert_called_once_with(dest.hash)

        # Packet is created with destination (not a link)
        mock_packet_class.assert_called_once()
        packet_args = mock_packet_class.call_args[0]
        self.assertEqual(packet_args[0], dest, "Packet destination should be the RFed dest, not a link")

        # Packet is sent
        packet.send.assert_called_once()


if __name__ == '__main__':
    unittest.main()