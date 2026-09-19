"""Test RFedClient.publish transport selection (DATA vs link Resource).

Per the Rust reference implementation (canonical, and ``@reticulum/rfed``
0.8.2), the ``rfed.channel.publish`` destination accepts both single
fire-and-forget DATA packets *and* link requests carrying oversized payloads
as an :class:`RNS.Resource`. The client therefore selects the transport by
size:

  * payload ≤ ``PUBLISH_DATA_MAX`` (431 B) — direct DATA packet, no link
  * payload >  ``PUBLISH_DATA_MAX``        — link + Resource, awaited to
    ``COMPLETE`` (the advertisement alone does not deliver the payload)
"""

import unittest
from unittest.mock import patch, MagicMock
import RNS

from dacar.rfed.client import RFedClient
from dacar.rfed.constants import CHANNEL_PUBLISH_NAME, PUBLISH_DATA_MAX

NODE = b"\x00" * 32


class TestPublishDirectTransport(unittest.TestCase):
    """Test that RFedClient sends small payloads directly without links."""

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
        """A within-MDU publish ensures path then sends a packet directly (no link)."""
        # Set up mocks
        node_hash = NODE
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


class TestPublishResourceTransport(unittest.TestCase):
    """Test that oversized publishes go out as a Resource over a link."""

    def setUp(self):
        """Set up a test client with fake RNS."""
        self.identity = RNS.Identity()
        self.rns = MagicMock()
        self.client = RFedClient(identity=self.identity, rns=self.rns)

        self.dest = MagicMock()
        self.dest.hash = b'\x02' * 16

    @patch('dacar.rfed.client.RNS.Resource')
    @patch('dacar.rfed.client.RNS.Link')
    @patch.object(RFedClient, '_ensure_path')
    @patch.object(RFedClient, '_out_destination')
    @patch.object(RFedClient, '_node_identity')
    def test_oversized_publish_sends_resource_over_link(
        self,
        mock_node_identity,
        mock_out_destination,
        mock_ensure_path,
        mock_link_class,
        mock_resource_class,
    ):
        """A payload beyond the MDU opens a link and sends an RNS.Resource."""
        mock_node_identity.return_value = self.identity
        mock_out_destination.return_value = self.dest

        # Establishing the link fires the established callback immediately.
        link = MagicMock()
        link.status = RNS.Link.ACTIVE
        mock_link_class.side_effect = lambda _dest, established_callback=None: (
            established_callback(link) if established_callback else None,
            link,
        )[1]

        # The Resource fires its concluded callback (COMPLETE) on creation.
        resource = MagicMock()
        resource.status = RNS.Resource.COMPLETE

        def resource_init(data, created_on, callback=None):
            self.assertEqual(data, b"x" * (PUBLISH_DATA_MAX + 1))
            self.assertIs(created_on, link)
            if callback:
                callback(resource)
            return resource

        mock_resource_class.side_effect = resource_init

        ok = self.client.send_publish(
            NODE, b"x" * (PUBLISH_DATA_MAX + 1)
        )

        self.assertTrue(ok)
        # Path was ensured for the publish destination before linking.
        mock_ensure_path.assert_called_once_with(self.dest.hash)
        # The link was opened to the RFed publish destination, and the
        # Resource was created over it.
        mock_link_class.assert_called_once()
        link_arg = mock_link_class.call_args[0][0]
        self.assertEqual(link_arg, self.dest)
        mock_resource_class.assert_called_once()

    @patch('dacar.rfed.client.RNS.Resource')
    @patch('dacar.rfed.client.RNS.Link')
    @patch.object(RFedClient, '_ensure_path')
    @patch.object(RFedClient, '_out_destination')
    @patch.object(RFedClient, '_node_identity')
    def test_failed_resource_reports_false(
        self,
        mock_node_identity,
        mock_out_destination,
        mock_ensure_path,
        mock_link_class,
        mock_resource_class,
    ):
        """A Resource that concludes non-COMPLETE (e.g. REJECTED) returns False."""
        mock_node_identity.return_value = self.identity
        mock_out_destination.return_value = self.dest

        link = MagicMock()
        link.status = RNS.Link.ACTIVE
        mock_link_class.side_effect = lambda _dest, established_callback=None: (
            established_callback(link) if established_callback else None,
            link,
        )[1]

        resource = MagicMock()
        resource.status = RNS.Resource.REJECTED

        def resource_init(data, created_on, callback=None):
            if callback:
                callback(resource)
            return resource

        mock_resource_class.side_effect = resource_init

        ok = self.client.send_publish(
            NODE, b"x" * (PUBLISH_DATA_MAX + 1)
        )
        self.assertFalse(ok)


if __name__ == '__main__':
    unittest.main()
