#!/usr/bin/python
import sys

sys.path.append("..")
import time

from Config import Config
from mininet.cli import CLI
from mininet.link import Link, TCLink, TCULink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Controller, CPULimitedHost, RemoteController, UserSwitch
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def __init__(self, config, **opts):
        Topo.__init__(self, **opts)

        self.config = config

        json = self.config.json
        self._bw = json["bandwith"]
        group1_switch = self.addSwitch('s1', datapath='user',dpid=json['sat']['group1']['datapath']['dpid'])
        group2_switch = self.addSwitch('s2', datapath='user',dpid=json['sat']['group2']['datapath']['dpid'])
        group3_switch = self.addSwitch('s3', datapath='user',dpid=json['sat']['group3']['datapath']['dpid'])
        group1_host = self.addHost('h1', cpu=.8/7, mac= json['sat']['group1']['host']['eth0'], ip=json['sat']['group1']['host']['ip_addr'])
        group2_host = self.addHost('h2', cpu=.8/7, mac= json['sat']['group2']['host']['eth0'], ip=json['sat']['group2']['host']['ip_addr'])
        group3_host = self.addHost('h3', cpu=.8/7, mac= json['sat']['group3']['host']['eth0'], ip=json['sat']['group3']['host']['ip_addr'])

        sr1_switch = self.addSwitch('s4', datapath='user',dpid=json['sat']['sr1']['datapath']['dpid'])
        sr2_switch = self.addSwitch('s5', datapath='user',dpid=json['sat']['sr2']['datapath']['dpid'])
        sr3_switch = self.addSwitch('s6', datapath='user',dpid=json['sat']['sr3']['datapath']['dpid'])
        sr1_host = self.addHost('h4', cpu=.8/7, mac= json['sat']['sr1']['host']['eth0'], ip=json['sat']['sr1']['host']['ip_addr'])
        sr2_host = self.addHost('h5', cpu=.8/7, mac= json['sat']['sr2']['host']['eth0'], ip=json['sat']['sr2']['host']['ip_addr'])
        sr3_host = self.addHost('h6', cpu=.8/7, mac= json['sat']['sr3']['host']['eth0'], ip=json['sat']['sr3']['host']['ip_addr'])

        dc1_switch = self.addSwitch('s7', datapath='user',dpid=json['dc']['dc1']['datapath']['dpid'])
        dc1_host = self.addHost('h7', cpu=.8/7, mac= json['dc']['dc1']['host']['eth0'], ip=json['dc']['dc1']['host']['ip_addr'])

        self.addLink(group1_host, group1_switch,port1=1, port2=json['link_port_num']['group1_to_host'], bw=self._bw)
        self.addLink(group1_switch, sr1_switch, port1=json['link_port_num']['group1_to_sr1'], port2=json['link_port_num']['sr1_to_group1'], bw=self._bw)
        self.addLink(group1_switch, sr2_switch, port1=json['link_port_num']['group1_to_sr2'], port2=json['link_port_num']['sr2_to_group1'], bw=self._bw)
        self.addLink(group1_switch, sr3_switch, port1=json['link_port_num']['group1_to_sr3'], port2=json['link_port_num']['sr3_to_group1'], bw=self._bw)

        self.addLink(group2_host, group2_switch,port1=1, port2=json['link_port_num']['group2_to_host'], bw=self._bw)
        self.addLink(group2_switch, sr1_switch, port1=json['link_port_num']['group2_to_sr1'], port2=json['link_port_num']['sr1_to_group2'], bw=self._bw)
        self.addLink(group2_switch, sr2_switch, port1=json['link_port_num']['group2_to_sr2'], port2=json['link_port_num']['sr2_to_group2'], bw=self._bw)
        self.addLink(group2_switch, sr3_switch, port1=json['link_port_num']['group2_to_sr3'], port2=json['link_port_num']['sr3_to_group2'], bw=self._bw)

        self.addLink(group3_host, group3_switch,port1=1, port2=json['link_port_num']['group3_to_host'], bw=self._bw)
        self.addLink(group3_switch, sr1_switch, port1=json['link_port_num']['group3_to_sr1'], port2=json['link_port_num']['sr1_to_group3'], bw=self._bw)
        self.addLink(group3_switch, sr2_switch, port1=json['link_port_num']['group3_to_sr2'], port2=json['link_port_num']['sr2_to_group3'], bw=self._bw)
        self.addLink(group3_switch, sr3_switch, port1=json['link_port_num']['group3_to_sr3'], port2=json['link_port_num']['sr3_to_group3'], bw=self._bw)

        self.addLink(sr1_host, sr1_switch, port1=1, port2=json["link_port_num"]["sr1_to_host"], bw=self._bw)
        self.addLink(sr2_host, sr2_switch, port1=1, port2=json["link_port_num"]["sr2_to_host"], bw=self._bw)
        self.addLink(sr3_host, sr3_switch, port1=1, port2=json["link_port_num"]["sr3_to_host"], bw=self._bw)
        self.addLink(dc1_host, dc1_switch, port1=1, port2=json["link_port_num"]["dc1_to_host"], bw=self._bw)

        self.addLink(dc1_switch, sr1_switch, port1=json["link_port_num"]["dc1_to_sr1"], port2=json['link_port_num']['sr1_to_dc1'], bw=self._bw)
        self.addLink(dc1_switch, sr2_switch, port1=json["link_port_num"]["dc1_to_sr2"], port2=json['link_port_num']['sr2_to_dc1'], bw=self._bw)
        self.addLink(dc1_switch, sr3_switch, port1=json["link_port_num"]["dc1_to_sr3"], port2=json['link_port_num']['sr3_to_dc1'], bw=self._bw)
 
def perfTest(config):
    "Create network and run simple performance test"
    topo = SingleSwitchTopo(config)
    # net = Mininet(topo=topo,host=CPULimitedHost, link=TCULink, controller=RemoteController(name='controller',ip='127.0.0.1',port=6633))
    net = Mininet(topo=topo,host=CPULimitedHost, link=TCULink, controller=RemoteController(name='controller',ip='127.0.0.1',port=6653))
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
    config_path_ = '/home/ubuntu/ryu/ryu/app/dsSatellite/Config/dsconfig.json'
    config  = Config.Config(config_path_)
    perfTest(config)
