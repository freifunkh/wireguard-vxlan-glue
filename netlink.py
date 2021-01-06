import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from json import loads as json_loads
from textwrap import wrap
from typing import Dict, List
from datetime import datetime, timedelta
import signal

from pyroute2 import WireGuard, IPRoute
import argparse
import signal
import os
import time

import ipaddress
import re


def mac2eui64(mac, prefix=None):
    """
    Convert a MAC address to a EUI64 identifier
    or, with prefix provided, a full IPv6 address
    """
    # http://tools.ietf.org/html/rfc4291#section-2.5.1
    eui64 = re.sub(r"[.:-]", "", mac).lower()
    eui64 = eui64[0:6] + "fffe" + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) | 2)[2:].zfill(2) + eui64[2:]

    if prefix is None:
        return ":".join(re.findall(r".{4}", eui64))
    else:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            euil = int("0x{}".format(eui64), 16)
            return "{}/{}".format(net[euil], net.prefixlen)
        except Exception:  # pylint: disable=broad-except
            return

#from wgkex.common.utils import mac2eui64

TIMEOUT = timedelta(minutes=3)

class WireGuardPeer:

    def __init__(self, public_key: str, latest_handshake : int = None,
                 is_installed : bool = False):
        self.public_key = public_key
        self.latest_handshake = latest_handshake
        self.is_installed = is_installed

    @property
    def lladdr(self) -> str:
        m = hashlib.md5()

        m.update(self.public_key.encode("ascii"))
        hashed_key = m.hexdigest()
        hash_as_list = wrap(hashed_key, 2)
        temp_mac = ":".join(["02"] + hash_as_list[:5])

        lladdr = re.sub(r"/\d+$", "/128", mac2eui64(mac=temp_mac, prefix="fe80::/10"))
        return lladdr

    @property
    def is_established(self) -> bool:
        return (datetime.now() - self.latest_handshake) < TIMEOUT

    @property
    def needs_config(self) -> bool:
        return self.is_established != self.is_installed

    """WireGuardPeer describes complete configuration for a specific WireGuard client

    Attributes:
        public_key: WireGuard Public key
        domain: Domain Name of the WireGuard peer
        lladdr: IPv6 lladdr of the WireGuard peer
        wg_interface: Name of the WireGuard interface this peer will use
        vx_interface: Name of the VXLAN interface we set a route for the lladdr to
        remove: Are we removing this peer or not?
    """

class ConfigManager:

    def __init__(self, wg_interface : str, vx_interface : str):
        self.all_peers = []
        self.wg_interface = wg_interface
        self.vx_interface = vx_interface

    def find_by_public_key(self, public_key : str) -> [WireGuardPeer]:
        peer = list(filter(lambda p: p.public_key == public_key, self.all_peers))
        assert(len(peer) <= 1)
        return peer

    def pull_from_wireguard(self):
        with WireGuard() as wg:
            clients = wg.info(self.wg_interface)[0].WGDEVICE_A_PEERS.value

            for client in clients:
                latest_handshake = client.WGPEER_A_LAST_HANDSHAKE_TIME["tv_sec"]
                public_key = client.WGPEER_A_PUBLIC_KEY["value"].decode("utf-8")

                peer = self.find_by_public_key(public_key)
                if len(peer) < 1:
                    peer = WireGuardPeer(public_key)
                    self.all_peers.append(peer)
                else:
                    peer = peer[0]

                peer.latest_handshake = datetime.fromtimestamp(latest_handshake)

    def push_vxlan_configs(self, force_remove = False):
        for peer in self.all_peers:
            if force_remove:
                if not peer.is_installed: continue
                new_state = False
            else:
                if not peer.needs_config: continue
                new_state = peer.is_established

            with IPRoute() as ip:
                ip.fdb(
                    "append" if new_state else "del",
                    ifindex=ip.link_lookup(ifname=self.vx_interface)[0],
                    # mac 00:00:00:00:00:00 means automatic learning
                    lladdr="00:00:00:00:00:00",
                    dst=re.sub(r"/\d+$", "", peer.lladdr),
                )

            with IPRoute() as ip:
                ip.route(
                    "add" if new_state else "del",
                    dst=peer.lladdr,
                    oif=ip.link_lookup(ifname=self.wg_interface)[0],
                )

            if new_state:
                print(f'Installed route and fdb entry for {peer.public_key} ({self.wg_interface}, {self.vx_interface})')
            else:
                print(f'Removed route and fdb entry for {peer.public_key} ({self.wg_interface}, {self.vx_interface}).')

            peer.is_installed = new_state

    def cleanup(self):
        self.push_vxlan_configs(force_remove=True)


def check_iface_type(iface, type):
    if not os.path.exists(f'/sys/class/net/{iface}'):
        print(f'Iface {iface} does not exist! Exiting...')
        exit(1)

    with open(f'/sys/class/net/{iface}/uevent', 'r') as f:
        for line in f.readlines():
            l = line.replace('\n', '').split('=')
            if l[0] == 'DEVTYPE' and l[1] != type:
                print(f'Iface {iface} is wrong type! Should be {type}, but is {l[1]}. Exiting...')
                exit(1)


if __name__ == '__main__':

    class Args:
        def __init__(self):
            self.wireguard=[]
            self.vxlan=[]

    parser = argparse.ArgumentParser(description='Process some interfaces.')
    parser.add_argument('-c', '--cfg', metavar='CONFIGPATH', type=str,
                    help='ignore -w and -x and read a configfile instead')
    parser.add_argument('-w', '--wireguard', metavar='IFACE', type=str, nargs='+',
                    help='add an wireguard interfaces', default=[])
    parser.add_argument('-x', '--vxlan', metavar='IFACE', type=str, nargs='+',
                    help='add an vxlan interfaces', default=[])

    args = parser.parse_args()

    if args.cfg is not None:
        if any((args.wireguard, args.vxlan)):
            print("Please use either cfg- or 'wireguard and vxlan'-parameters, not both.")
            exit(1)
        # overwrite args
        with open(args.cfg) as configfile:
            data = configfile.read()
            configobject=json_loads(data)
            args=Args()
            args.wireguard=configobject['interfaces']['wireguard']
            args.vxlan=configobject['interfaces']['vxlan']

    if len(args.wireguard) != len(args.vxlan):
        print('Please specify equal amount of vxlan and wireguard interfaces.')
        exit(1)

    if len(args.wireguard) < 1:
        print('Please specify at least one vxlan and one wireguard interface.')
        exit(1)

    managers = []

    for i in range(len(args.wireguard)):
        check_iface_type(args.wireguard[i], 'wireguard')
        check_iface_type(args.vxlan[i], 'vxlan')

        managers.append(ConfigManager(args.wireguard[i], args.vxlan[i]))

    should_stop = False

    def handler(signum, frame):
        global should_stop
        if signum == signal.SIGTERM:
            print('Received SIGTERM. Exiting...')
        elif signum == signal.SIGINT:
            print('Received SIGINT. Exiting...')
        should_stop = True

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)

    while not should_stop:
        for manager in managers:
            manager.pull_from_wireguard()
            manager.push_vxlan_configs()

        for i in range(100):
            if should_stop:
                break
            time.sleep(0.1)

    for manager in managers:
        manager.cleanup()
