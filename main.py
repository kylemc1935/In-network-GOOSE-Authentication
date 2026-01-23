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
    H2 = net.addHost('H2', cls=Host, ip='1.1.1.2', defaultRoute='1.1.1.1',mac='00:00:00:00:00:02')

    info( '*** Setting link parameters\n')

    info( '*** Adding links\n')
    net.addLink(H1, S1)
    net.addLink(S1, S2)
    net.addLink(S2, H2)

    info( '*** Starting network\n')
    net.build()

    info( '*** Starting networking devices \n')
    net.get('S1').start([])
    net.get('S2').start([])
    info( '\n')

    info('**Setting flows to prevent duplication of packets ****\n')
    S1.cmd('ovs-ofctl del-flows S1')
    S1.cmd("ovs-ofctl add-flows S1 'in_port=S1-eth1, actions=drop'")
    S2.cmd('ovs-ofctl del-flows S2')
    S2.cmd("ovs-ofctl add-flows S2 'in_port=S2-eth2, actions=drop'")

    info( '*** Preparing custom sgsim scripts \n')
    CLI.do_run_experiment = experiment
    info( '*** Network started *** \n' )
    CLI(net)
    net.stop()

def experiment(self, line):
    net = self.mn
    info('Starting experiment... \n')



    net.get('H2').cmdPrint(
                'xterm -geometry 70x20-35-35 -fa "Monospace" -fs 8 -T "H - Receiver" -e "python3 receive_goose.py ; exec bash"&')

    info("=== Running experiment")


    net.get('H1').cmdPrint('xterm -geometry 70x20+35-35 -fa "Monospace" -fs 8 -T "H1 - Sending" -e "python3 send_goose.py; exec bash"&')




    info("===ALL EXPERIMENTS FINISHED===\n")



if __name__ == '__main__':
    setLogLevel( 'info' )
    set_topology_s2()



