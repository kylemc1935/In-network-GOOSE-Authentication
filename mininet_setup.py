#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import  Host
from mininet.node import OVSKernelSwitch #, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import subprocess

duration = 10

def set_topology_s2():
    net = Mininet( topo=None,
                   build=False,
                   ipBase='1.0.0.0/8')

    switchType = OVSKernelSwitch

    info( '*** Starting networking devices\n')
    S1 = net.addSwitch('S1', cls=switchType, dpid='1',failMode='standalone')
    S2 = net.addSwitch('S2', cls=switchType, dpid='2',failMode='standalone')

    info( '*** Starting hosts \n')
    H1 = net.addHost('H1', cls=Host, ip='1.1.1.1', defaultRoute='1.1.1.2',mac='00:00:00:00:00:01')
    # H2 = net.addHost('H2', cls=Host, ip='1.1.1.2', defaultRoute='1.1.1.1',mac='00:00:00:00:00:02')

    info( '*** Adding links\n')
    net.addLink(H1, S1)
    net.addLink(S1, S2)
    # net.addLink(S2, H2)
    net.addLink(S2, H1)

    info( '*** Starting network\n')
    net.build()

    info( '*** Starting networking devices \n')
    net.get('S1').start([])
    net.get('S2').start([])
    info( '\n')

    S1.cmd('ovs-ofctl del-flows S1')
    S1.cmd('ovs-ofctl add-flow S1 "priority=200,in_port=1,dl_type=0x88b8,actions=drop"')
    S1.cmd('ovs-ofctl add-flow S1 "priority=0,actions=normal"')

    S2.cmd('ovs-ofctl del-flows S2')
    S2.cmd('ovs-ofctl add-flow S2 "priority=200,in_port=1,dl_type=0x88b8,actions=drop"')
    S2.cmd('ovs-ofctl add-flow S2 "priority=0,actions=normal"')

    # drop inbound GOOSE frames arriving on the return link for when using only one host to prevent, reinserting of packetes to the network
    H1.cmd('ebtables -F')
    H1.cmd('ebtables -A INPUT -i H1-eth1 -p 0x88b8 -j DROP')
    H1.cmd('ebtables -A INPUT -i H1-eth1 -j DROP')

    info( '*** Network started *** \n' )
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    set_topology_s2()



