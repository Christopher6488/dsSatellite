# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import datetime as dt
from operator import attrgetter

import matplotlib.pyplot as plt
import networkx as nx
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import arp, ether_types, ethernet, icmp, ipv4, packet, tcp
from ryu.ofproto import ether, ofproto_v1_3

from Config import Config
from virtue_topo import virtue_topo
from utils.utils import check_class
from utils.packetout import add_flow, clear_all_flow_tables, clear_all_meter_tables, send_packet
from monitor import Monitor
from Algorithm.ShortestPath import ShortestPath
from utils.packetout import request_stats

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.config_path =  '/home/ubuntu/ryu/ryu/app/dsSatellite/Config/dsconfig.json'
        self.config = Config.Config(self.config_path)

        self.current_topo = nx.Graph()
        self.monitor = Monitor(self.config)

        self.algorithm = ShortestPath(self.config, monitor)
        self.time_expand_topo = virtue_topo.create_virtue_topo(self.config)
        self.topo_thread = hub.spawn(self._create_topo)
        self.all_pairs_shortest_paths = {}
        self.monitor.next_table = 1
        
        self.timeStamp=0

        if(self.config.json["enable_monitor"]):
            self.monitor_thread = hub.spawn(monitor.logger())

        if(self.config.json["enable_show_topo"]):
            self.show_topo_thread = hub.spawn(self._show_topo)


        self.arp_table = {self.config.json['sat']['group1']['host']['ip_addr']: self.config.json['sat']['group1']['host']['eth0'],
                          self.config.json['sat']['group2']['host']['ip_addr']: self.config.json['sat']['group2']['host']['eth0'],
                          self.config.json['sat']['group3']['host']['ip_addr']: self.config.json['sat']['group3']['host']['eth0'],
                          self.config.json['sat']['sr1']['host']['ip_addr']: self.config.json['sat']['sr1']['host']['eth0'],
                          self.config.json['sat']['sr2']['host']['ip_addr']: self.config.json['sat']['sr2']['host']['eth0'],
                          self.config.json['sat']['sr3']['host']['ip_addr']: self.config.json['sat']['sr3']['host']['eth0'],
                          self.config.json['dc']['dc1']['host']['ip_addr']: self.config.json['dc']['dc1']['host']['eth0']}
        
        self.dpid_table = {self.config.json['sat']['group1']['datapath']['dpid_d']: 'group1', 
                                            self.config.json['sat']['group2']['datapath']['dpid_d']: 'group2', 
                                            self.config.json['sat']['group3']['datapath']['dpid_d']: 'group3',
                                            self.config.json['sat']['sr1']['datapath']['dpid_d']: 'sr1',
                                            self.config.json['sat']['sr2']['datapath']['dpid_d']: 'sr2',
                                            self.config.json['sat']['sr3']['datapath']['dpid_d']: 'sr3',
                                            self.config.json['dc']['dc1']['datapath']['dpid_d']: 'dc1'}
        
        
        self.last_time = dt.datetime(year=2020,month=8,day=18,hour=dt.datetime.now().hour,minute=dt.datetime.now().minute)
        self.sleepTime = 1.0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("switch_features_handler called!")
        dp = ev.msg.datapath
        self.logger.info("datapath id is %016d", dp.id)
    
    def install_meter_table(self, dp):
        self.logger.info("install_meter_table_called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        for i in range(1,10):
            meter_mod = parser.OFPMeterMod(datapath=dp, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=i, bands=[parser.OFPMeterBandDrop(rate=5000, burst_size=0)])
            dp.send_msg(meter_mod)

    def install_to_host_flow_entry(self, dp):
        self.logger.info("install_to_host_flow_entry called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        host = self.dpid_table[dp.id]
        node_class = check_class(host)
        
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=self.config.json[node_class][host]['host']['ip_addr'])
        out_port_num = self.config.json['link_port_num'][host+'_to_host']
        actions = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                                                        [parser.OFPActionOutput(port=out_port_num)])
        inst = [actions]
        add_flow(dp, table_id=0, priority=1, match=match, inst=inst)

    def install_pointer_table(self, dp):
        self.logger.info("install_pointer_table_called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = parser.OFPInstructionGotoTable(self.next_table)
        inst =  [actions]
        add_flow(dp, table_id=0, priority=0, match=match, inst=inst)
    
    def install_table_miss_flow_entry(self, dp):
        self.logger.info("install_table_miss_flow_entry called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                                                        [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                                                                        ofproto.OFPCML_NO_BUFFER)])
        inst = [actions]
        add_flow(dp, table_id=1,  priority=0, match=match, inst=inst)
        add_flow(dp, table_id=2,  priority=0, match=match, inst=inst)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = ev.msg.match['in_port']

        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore IPV6
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("This is ARP")
            self.handle_arp(dp, in_port, pkt)

        if (eth.ethertype == ether_types.ETH_TYPE_IP):
            self.logger.info("This is packet in message")
            self.handle_ip(dp, ev.msg)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016d', datapath.id)
                self.monitor.datapaths[datapath.id] = datapath

                #clear all old flow tables
                clear_all_flow_tables(datapath)
                #clear all meter tables
                clear_all_meter_tables(datapath)
                # install to host flow entry
                self.install_to_host_flow_entry(datapath)
                # install table-miss flow entry
                self.install_table_miss_flow_entry(datapath)
                # install pointer table
                self.install_pointer_table(datapath)
                # install meter table
                self.install_meter_table(datapath)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016d', datapath.id)
                del self.monitor.datapaths[datapath.id]

    def handle_ip(self, dp, msg):
        self.logger.info("handle_ip called!")
        return
        
    def _monitor(self):
        hub.sleep(10)
        while True:
            for dp in self.datapaths.values():
                request_stats(dp)
            hub.sleep(self.config.json['sleep_time'])
    
    def _show_topo(self):
        plt.ion()
        while True:
            virtue_topo.show_topo(self.current_topo)
            hub.sleep(1)
        plt.ioff()
        plt.show()
        
    def _create_topo(self):
        hub.sleep(30)
        current_time = dt.datetime(year=2020, month=8, day=18, hour=4, minute=26)
        self.logger.info("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.info("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.info("The number of datapaths is: %d", len(self.datapaths))
        for key in self.datapaths.keys():
            self.logger.info(key)
        self.logger.info("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.info("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.info("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        while len(self.datapaths) == 6:
            if current_time != self.last_time:
                self.current_topo = self.time_expand_topo.slice_topo(current_time)
                self.logger.info("Start Update!")
                self.algorithm.update_meter_table()
                self.algorithm.update_flow_table()
                self.algorithm.update_pointer_table()
                self.algorithm.clear_old_flow_table()

                self.last_time = current_time
            self.monitor.next_table = (3 - pow(-1, self.next_table)) / 2
            hub.sleep(1000000)
    

    def install_init_meter_table(self):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
    
            meter_mod = parser.OFPMeterMod(datapath=dp, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=1, bands=[parser.OFPMeterBandDrop(rate=10000, burst_size=0)])
            dp.send_msg(meter_mod)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        self.monitor.logger(ev)


    def handle_arp(self, dp, port, pkt):
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

        # checking if it's arp packet return None if not arp packet
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        # checking if the destination address exists in arp_table returns NONE otherwise
        if self.arp_table.get(pkt_arp.dst_ip) == None:
            return
        get_mac = self.arp_table[pkt_arp.dst_ip]

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether.ETH_TYPE_ARP,
                dst=pkt_ethernet.src,
                src=get_mac
            )
        )

        pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=get_mac,
                src_ip=pkt_arp.dst_ip,
                dst_mac=pkt_arp.src_mac,
                dst_ip=pkt_arp.src_ip
            )
        )

        print('ARP REPLYED!')
        self.send_packet(dp, port, pkt)

    # PacketOut used to send packet from controller to switch
