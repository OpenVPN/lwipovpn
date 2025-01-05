OpenVPN lwipovpn tun/tap emulator
=================================
Overview
--------
This is a small helper tool based on [lwIP - A Lightweight TCP/IP stack](https://savannah.nongnu.org/projects/lwip/)
to emulate a tun/tap device in userspace without having an effect on the system that the lwip is running on.

This allows:

 - testing a VPN connection without root
 - pinging the connected client
 - running tests against the client and the lwip stack
 - using lwip example applications
   - lwip http server
   - lwip iperf server
   - ...
 - better automated testing

Features
--------
 - IPv4 Support
 - IPv6 Support
 - automatic configuration of IPv4 and IPv6 addresses
 - tap or tun emulation
 - write pcap file 


Enabled apps
------------
lwip comes a number of demo/default apps. lwipovpn has enabled most of them to be helpful in testing. Further apps
can be enabled/implemented to allow even more testing. 

 - netio (https://www.nwlab.net/art/netio/netio.html)
 - iperf 2 (https://iperf.fr/)
 - http server
 - shell (a simple shell that can be used with telnet to make some network diagnostics)
 - tcp echo (port 7)
 - udp echo (port 7)


PCAP File Support
-----------------
If the environment variable `LWIP_PCAP_FILE` is e.g. by setting it from OpenVPN via 

    setenv LWIP_PCAP_FILE /tmp/lwip.pcap

then lwipovpn will write all packets send/received into this pcap file. If the file 
already exists, the new packets will be appended to it.

Limitations
-----------
 - Data through is limited. Iperf performance is at 20 MBit/s. This is not a problem for the indented purpose of
   this tool which is for testing.
 - Windows port is currently missing. It should be possible to use pipes instead of a socketpair with 
   AF_UNIX/SOCK_DGRAM to support Windows. This might also require adding a length header to ensure that always
   full packets are read/written.
 - LWIP does not have a netmask for IPv6 addresses. Addresses are always assumed to be /64
 - Routes are ignored and lwipovpn assumes everything to be reachable via OpenVPN


Git checkout
------------
Be sure that lwipovpn has been checked with submodule recursion enabled like this:

    git clone --recursive https://github.com/openvpn/lwipovpn

or by enabling them in already checkout clone by using the git submodule commands:
   
    cd lwipovpn
    git submodule init
    git submodule update

Building
--------
This project uses the CMake build system.

    cmake -B lwipovpnbuild -S lwipovpn
    cmake --build lwipovpnbuild
    
This should result in a `lwipovpnbuild/lwipovpn` binary that can be used with OpenVPN master and 
OpenVPN 2.7.x like this:

    openvpn --config client.ovpn --dev-node unix:lwipovpnbuild/lwipovpn

Implementation
--------------
The OpenVPN process will call `(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)` for connection between OpenVPN and lwipovpn
and execute ovpnlwip and pass the second fd to the process. The rest of the configuration is passed as environment
variables.
 - TUNTAP_SOCKET_FD: the fd number of the AF_UNIX socket
 - TUN_UNIXAF_PATH: alternative to TUNTAP_SOCKET_FD containing a unix domain socket file path.
 - TUNTAP_DEV_TYPE: the type of device to emulate: tap or tun
 - TUNTAP_MTU: MTU of the emulated devices
 - ifconfig_gateway: Gateway address. Derived from route-gateway in OpenVPN
 - ifconfig_local, ifconfig_netmask, ifconfig_netmask, ifconfig_ipv6_local, ifconfig_ipv6_netbits as described in the 
   openvpn manual page.

Both the OpenVPN --dev-node unix: and the lwipovpn can be used for other purposes but especially lwipovpn is currently
very OpenVPN specific as it uses the OpenVPN environment variables names. 

License
-------
This tool is under the same (3-Clause BSD License)[COPYING] as lwIP itself. 