# wireguard-vxlan-glue

This project is based on ffmucs wgkex, and drops everything mqtt related, as routers in hannover have to be registered manually and we really just want wireguard, and not mqtt infrastructure.
Thanks to munich for their outstanding work and ongoing support!

# WireGuard Key Exchange

WireGuard Key Exchange is a tool consisting of two parts: a frontend (broker) and a backend (worker). The frontend (broker) is where the client can push (register) its key before connecting. The backend (worker) is injecting those keys into a WireGuard instance.
This tool is intended to facilitate running BATMAN over VXLAN over WireGuard as a means to create encrypted high-performance mesh links.

## Installation

* Put this file on a server, and run it using a service - indefinitely.
* Have another daemon adding wireguard peers from our repo.

## Configuration

* Specify interfaces using `-w` and `-x` and have equal amounts of them.
* Or specify a path to a configfile via `-c` like the provided [netlink_cfg.json.example](netlink_cfg.json.example).


