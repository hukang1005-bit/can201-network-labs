from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host, OVSKernelSwitch, RemoteController
from mininet.term import makeTerm


def build_network():
    net = Mininet(topo=None, autoSetMacs=False, build=False)

    # Add controller
    net.addController("c1", controller=RemoteController, ip="127.0.0.1", port=6633)

    # Add hosts
    server1 = net.addHost("server1", cls=Host, defaultRoute=None)
    server2 = net.addHost("server2", cls=Host, defaultRoute=None)
    client = net.addHost("client", cls=Host, defaultRoute=None)

    # Add switch
    s1 = net.addSwitch(
        "s1", cls=OVSKernelSwitch, failMode="secure", protocols="OpenFlow13"
    )

    # Add links
    net.addLink(server1, s1)
    net.addLink(server2, s1)
    net.addLink(client, s1)

    # Build network
    net.build()

    # Set MAC addresses for interfaces
    server1.setMAC(intf="server1-eth0", mac="00:00:00:00:00:01")
    server2.setMAC(intf="server2-eth0", mac="00:00:00:00:00:02")
    client.setMAC(intf="client-eth0", mac="00:00:00:00:00:03")

    # Assign IP addresses to interfaces
    server1.setIP(intf="server1-eth0", ip="10.0.1.2/24")
    server2.setIP(intf="server2-eth0", ip="10.0.1.3/24")
    client.setIP(intf="client-eth0", ip="10.0.1.5/24")

    # Start network
    net.start()

    # Start xterm for hosts
    net.terms += makeTerm(server1)
    net.terms += makeTerm(server2)
    net.terms += makeTerm(client)

    # Run CLI mode
    try:
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build_network()
