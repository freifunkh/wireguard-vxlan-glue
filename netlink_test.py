"""Unit tests for netlink.py"""
import unittest
import mock
from datetime import timedelta
from datetime import datetime

# pyroute2 decides imports based on platform. WireGuard is specific to Linux only. Mock pyroute2.WireGuard so that
# any testing platform can execute tests.
import sys

sys.modules["pyroute2"] = mock.MagicMock()
sys.modules["pyroute2.WireGuard"] = mock.MagicMock()
sys.modules["pyroute2.IPRoute"] = mock.MagicMock()
from pyroute2 import WireGuard
from pyroute2 import IPRoute
import netlink

_WG_CLIENT_ADD = netlink.WireGuardPeer(
    public_key="public_key", latest_handshake=datetime.now(), is_installed=False
)
_WG_CLIENT_DEL = netlink.WireGuardPeer(
    public_key="public_key",
    latest_handshake=(datetime.now() - (netlink.TIMEOUT+timedelta(seconds=1))), is_installed=True
)

_WG_PEER_STALE = mock.Mock()
_WG_PEER_STALE.WGPEER_A_PUBLIC_KEY = {"value": b"WGPEER_A_PUBLIC_KEY_STALE"}
_WG_PEER_STALE.WGPEER_A_LAST_HANDSHAKE_TIME = {
    "tv_sec": int((datetime.now() - (netlink.TIMEOUT+timedelta(seconds=1))).timestamp())
}

_WG_PEER = mock.Mock()
_WG_PEER.WGPEER_A_PUBLIC_KEY = {"value": b"WGPEER_A_PUBLIC_KEY"}
_WG_PEER.WGPEER_A_LAST_HANDSHAKE_TIME = {
    "tv_sec": int((datetime.now() - timedelta(seconds=3)).timestamp())
}

_WG_PEER_NO_HANDSHAKE = mock.Mock()
_WG_PEER_NO_HANDSHAKE.WGPEER_A_PUBLIC_KEY = {"value": b"WGPEER_A_PUBLIC_KEY_MISSING_HANDSHAKE"}
_WG_PEER_NO_HANDSHAKE.WGPEER_A_LAST_HANDSHAKE_TIME = {
    "something": "unrelated"
}


def _get_wg_mock(peer):
    info_mock = mock.Mock()
    info_mock.WGDEVICE_A_PEERS.value = [peer]
    wg_instance = WireGuard()
    wg_info_mock = wg_instance.__enter__.return_value
    wg_info_mock.set.return_value = {"WireGuard": "set"}
    wg_info_mock.info.return_value = [info_mock]
    return wg_info_mock


class ConfigManagerTest(unittest.TestCase):
    def setUp(self) -> None:
        iproute_instance = IPRoute()
        self.route_info_mock = iproute_instance.__enter__.return_value
        self.cm = netlink.ConfigManager("some_wg_interface", "some_vx_interface")
        # self.addCleanup(mock.patch.stopall)

    def test_pull_from_wireguard_success_with_non_stale_peer(self):
        """Tests pull_from_wireguard add non-stale peers to all_peers."""
        wg_info_mock = _get_wg_mock(_WG_PEER)
        self.cm.pull_from_wireguard()
        self.assertListEqual([p.public_key for p in self.cm.all_peers], ["WGPEER_A_PUBLIC_KEY"])

    def test_pull_from_wireguard_success_with_stale_peer(self):
        """Tests pull_from_wireguard even add stale peers to all_peers."""
        wg_info_mock = _get_wg_mock(_WG_PEER_STALE)
        self.cm.pull_from_wireguard()
        self.assertListEqual([p.public_key for p in self.cm.all_peers], ["WGPEER_A_PUBLIC_KEY_STALE"])

    def test_pull_from_wireguard_success_with_missing_handshake_peer(self):
        """Tests pull_from_wireguard no operation on handshake-less peers."""
        wg_info_mock = _get_wg_mock(_WG_PEER_NO_HANDSHAKE)
        self.cm.pull_from_wireguard()
        self.assertListEqual(self.cm.all_peers, [])

    def test_pull_from_wireguard_success_idempotency(self):
        """Tests pull_from_wireguard no change, unless input changes."""
        wg_info_mock = _get_wg_mock(_WG_PEER)
        self.cm.pull_from_wireguard()
        self.assertListEqual([p.public_key for p in self.cm.all_peers], ["WGPEER_A_PUBLIC_KEY"])
        self.cm.pull_from_wireguard()
        self.assertListEqual([p.public_key for p in self.cm.all_peers], ["WGPEER_A_PUBLIC_KEY"])

    def test_find_by_public_key_success(self):
        """Tests find_by_public_key, returns the correct peer."""
        reference_peer = netlink.WireGuardPeer("WGPEER_A_PUBLIC_KEY")
        self.cm.all_peers.append(reference_peer)

        self.assertListEqual(self.cm.find_by_public_key("WGPEER_A_PUBLIC_KEY"), [reference_peer])

    def test_find_by_public_key_fail(self):
        """Tests find_by_public_key, returns empty list if no matching peer found."""
        cm = netlink.ConfigManager("some_wg_interface", "some_vx_interface")
        reference_peer = netlink.WireGuardPeer("WGPEER_A_PUBLIC_KEY")
        cm.all_peers.append(reference_peer)

        self.assertListEqual(cm.find_by_public_key("WGPEER_AN_UNKNOWN_PUBLIC_KEY"), [])

    def test_find_by_public_key_duplicete(self):
        """Tests find_by_public_key, raises AssertionError if searched pubkey is not unique."""
        cm = netlink.ConfigManager("some_wg_interface", "some_vx_interface")
        reference_peer = netlink.WireGuardPeer("WGPEER_A_PUBLIC_KEY")
        cm.all_peers.append(reference_peer)
        cm.all_peers.append(reference_peer)

        with self.assertRaises(AssertionError):
            cm.find_by_public_key("WGPEER_A_PUBLIC_KEY")

    def test_push_vxlan_configs_add(self):
        """Test push_vxlan_configs for normal add operation."""
        self.route_info_mock.fdb.return_value = {"key": "value"}
        self.route_info_mock.route.return_value = {"key": "value"}
        cm = netlink.ConfigManager("some_wg_interface", "some_vx_interface")
        cm.all_peers.append(_WG_CLIENT_ADD)

        self.assertIsNone(cm.push_vxlan_configs())

        self.route_info_mock.route.assert_called_with(
            "add", dst="fe80::2e4:afff:fee2:6b5b/128", oif=mock.ANY, proto=netlink.RT_PROTO_ID
        )
        self.route_info_mock.fdb.assert_called_with(
            "append",
            ifindex=mock.ANY,
            lladdr="00:00:00:00:00:00",
            dst="fe80::2e4:afff:fee2:6b5b",
        )

    def test_push_vxlan_configs_force_remove(self):
        """Test push_vxlan_configs for forced removal of peers."""
        self.route_info_mock.fdb.return_value = {"key": "value"}
        self.route_info_mock.route.return_value = {"key": "value"}
        cm = netlink.ConfigManager("some_wg_interface", "some_vx_interface")
        cm.all_peers.append(_WG_CLIENT_ADD)

        self.assertIsNone(cm.push_vxlan_configs(force_remove=True))

        self.route_info_mock.route.assert_called_with(
            "del", dst="fe80::2e4:afff:fee2:6b5b/128", oif=mock.ANY, proto=netlink.RT_PROTO_ID
        )
        self.route_info_mock.fdb.assert_called_with(
            "del",
            ifindex=mock.ANY,
            lladdr="00:00:00:00:00:00",
            dst="fe80::2e4:afff:fee2:6b5b",
        )

    def test_push_vxlan_configs_del(self):
        """Test push_vxlan_configs for normal remove operation."""
        self.route_info_mock.fdb.return_value = {"key": "value"}
        self.route_info_mock.route.return_value = {"key": "value"}
        cm = netlink.ConfigManager("some_wg_interface", "some_vx_interface")
        cm.all_peers.append(_WG_CLIENT_DEL)

        self.assertIsNone(cm.push_vxlan_configs())

        self.route_info_mock.route.assert_called_with(
            "del", dst="fe80::2e4:afff:fee2:6b5b/128", oif=mock.ANY, proto=netlink.RT_PROTO_ID
        )
        self.route_info_mock.fdb.assert_called_with(
            "del",
            ifindex=mock.ANY,
            lladdr="00:00:00:00:00:00",
            dst="fe80::2e4:afff:fee2:6b5b",
        )


class WireGuardPeerTestCase(unittest.TestCase):
    def test_lladdr(self):
        dummy = netlink.WireGuardPeer("E2GuBSnyrKKG2mPIFc8tkEymTOTJcNH1WvF6N9KoWgs=")
        self.assertEqual("fe80::213:18ff:fe6e:f314/128", dummy.lladdr, "Calculated lladdr is wrong.")

    def test_is_established_recent(self):
        recent = netlink.WireGuardPeer("doesnotmatter", latest_handshake=datetime.now())
        self.assertTrue(recent.is_established, "Wrongly marked a recent peer as not established.")

    def test_is_established_stalled(self):
        stalled = netlink.WireGuardPeer("doesnotmatter",
                                        latest_handshake=datetime.now()-(timedelta(seconds=1)+netlink.TIMEOUT))
        assert False is stalled.is_established
        self.assertFalse(stalled.is_established, "Wrongly marked a stalled peer as established.")

    @mock.patch.object(netlink.WireGuardPeer, 'is_established')
    def test_needs_config_installed_pos(self, mock_wgp):
        mock_wgp.__get__ = mock.PropertyMock(return_value=False)
        established = netlink.WireGuardPeer("doesnotmatter", is_installed=True)

        self.assertTrue(established.needs_config, "Installed but not established peer does need configuration")

    @mock.patch.object(netlink.WireGuardPeer, 'is_established')
    def test_needs_config_installed_neg(self, mock_wgp):
        mock_wgp.__get__ = mock.PropertyMock(return_value=True)
        established = netlink.WireGuardPeer("doesnotmatter", is_installed=True)

        self.assertFalse(established.needs_config, "Installed and established peer does not need configuration.")

    @mock.patch.object(netlink.WireGuardPeer, 'is_established')
    def test_needs_config_to_install_pos(self, mock_wgp):
        mock_wgp.__get__ = mock.PropertyMock(return_value=False)
        established = netlink.WireGuardPeer("doesnotmatter", is_installed=False)

        self.assertFalse(established.needs_config, "Not installed, not established peer does not need configuration.")

    @mock.patch.object(netlink.WireGuardPeer, 'is_established')
    def test_needs_config_to_install_neg(self, mock_wgp):
        mock_wgp.__get__ = mock.PropertyMock(return_value=True)
        established = netlink.WireGuardPeer("doesnotmatter", is_installed=False)

        self.assertTrue(established.needs_config, "Not installed yet established peer does need configuration.")


if __name__ == "__main__":
    unittest.main()
