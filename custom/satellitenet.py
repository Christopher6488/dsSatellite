#!/usr/bin/python
import sys

sys.path.append("..")
import time

from Config import Config
from mininet.cli import CLI
from mininet.link import Link, TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Controller, CPULimitedHost, RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def __init__(self, config, **opts):
        Topo.__init__(self, **opts)

        self.config = config

        json = self.config.json
        group1_switch = self.addSwitch('s1')
        group2_switch = self.addSwitch('s2')
        group3_switch = self.addSwitch('s3')
        group1_host = self.addHost('h1', cpu=.5/7, mac= json['sat']['group1']['host']['eth0'], ip=json['sat']['group1']['host']['ip_addr'])
        group2_host = self.addHost('h2', cpu=.5/7, mac= json['sat']['group2']['host']['eth0'], ip=json['sat']['group2']['host']['ip_addr'])
        group3_host = self.addHost('h3', cpu=.5/7, mac= json['sat']['group3']['host']['eth0'], ip=json['sat']['group3']['host']['ip_addr'])

        sr1_switch = self.addSwitch('s4')
        sr2_switch = self.addSwitch('s5')
        sr3_switch = self.addSwitch('s6')
        sr1_host = self.addHost('h4', cpu=.5/7, mac= json['sat']['sr1']['host']['eth0'], ip=json['sat']['sr1']['host']['ip_addr'])
        sr2_host = self.addHost('h5', cpu=.5/7, mac= json['sat']['sr2']['host']['eth0'], ip=json['sat']['sr2']['host']['ip_addr'])
        sr3_host = self.addHost('h6', cpu=.5/7, mac= json['sat']['sr3']['host']['eth0'], ip=json['sat']['sr3']['host']['ip_addr'])

        dc_switch = self.addSwitch('s7')
        dc_host = self.addHost('h7', cpu=.5/7, mac= json['dc']['host']['eth0'], ip=json['dc']['host']['ip_addr'])

        self.addLink(group1_host, group1_switch,port1=1, port2=json['link_port_num']['group1_to_host'])
        self.addLink(group1_switch, sr1_switch, port1=json['link_port_num']['group1_to_sr1'], port2=json['link_port_num']['sr1_to_group1'])
        self.addLink(group1_switch, sr2_switch, port1=json['link_port_num']['group1_to_sr2'], port2=json['link_port_num']['sr2_to_group1'])
        self.addLink(group1_switch, sr3_switch, port1=json['link_port_num']['group1_to_sr3'], port2=json['link_port_num']['sr3_to_group1'])

        self.addLink(group2_host, group2_switch,port1=1, port2=json['link_port_num']['group2_to_host'])
        self.addLink(group2_switch, sr1_switch, port1=json['link_port_num']['group2_to_sr1'], port2=json['link_port_num']['sr1_to_group2'])
        self.addLink(group2_switch, sr2_switch, port1=json['link_port_num']['group2_to_sr2'], port2=json['link_port_num']['sr2_to_group2'])
        self.addLink(group2_switch, sr3_switch, port1=json['link_port_num']['group2_to_sr3'], port2=json['link_port_num']['sr3_to_group2'])

        self.addLink(group3_host, group3_switch,port1=1, port2=json['link_port_num']['group3_to_host'])
        self.addLink(group3_switch, sr1_switch, port1=json['link_port_num']['group3_to_sr1'], port2=json['link_port_num']['sr1_to_group3'])
        self.addLink(group3_switch, sr2_switch, port1=json['link_port_num']['group3_to_sr2'], port2=json['link_port_num']['sr2_to_group3'])
        self.addLink(group3_switch, sr3_switch, port1=json['link_port_num']['group3_to_sr3'], port2=json['link_port_num']['sr3_to_group3'])

        self.addLink(dc_switch, sr1_switch, port1=json["link_port_num"]["dc_to_sr1"], port2=json['link_port_num']['sr1_to_dc'])
        self.addLink(dc_switch, sr2_switch, port1=json["link_port_num"]["dc_to_sr2"], port2=json['link_port_num']['sr2_to_dc'])
        self.addLink(dc_switch, sr3_switch, port1=json["link_port_num"]["dc_to_sr3"], port2=json['link_port_num']['sr3_to_dc'])
 
def perfTest(config):
    "Create network and run simple performance test"
    topo = SingleSwitchTopo(config)
    net = Mininet(topo=topo,host=CPULimitedHost, link=TCLink, controller=RemoteController)
    net.start()
    # print "Dumping host connections"
    # dumpNodeConnections(net.hosts)
    # dumpNodeConnections(net.switches)
    # time.sleep(10)
    # print "Testing network connectivity"
    # net.pingAll()
    CLI(net)
    # print "Testing bandwidth between h1 and h4"
    # group1, dc = net.get('group1', 'dc')
    # net.iperf((group1, dc))
    net.stop()
 
if __name__=='__main__':
    setLogLevel('info')
    config_path_ = '/home/ubuntu/ryu/ryu/app/dsSatellite/Config/config.json'
    config  = Config.Config(config_path_)
    perfTest(config)
