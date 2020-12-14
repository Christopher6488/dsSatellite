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
import time
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
from utils.mydict import add_two_dim_dict

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.config_path =  '/home/ubuntu/ryu/ryu/app/dsSatellite/Config/dsconfig.json'
        self.config = Config.Config(self.config_path)

        self.current_topo = nx.Graph()
        self.time_expand_topo = virtue_topo.create_virtue_topo(self.config)
        self.topo_thread = hub.spawn(self._create_topo)
        self.time_thread = hub.spawn(self._time_simulator)
        self.all_pairs_shortest_paths = {}
        self.next_table = 1
        self.logger.setLevel(self.config.json["LOGGER_LEVEL"])
        
        self.datapaths = {}
        self.lastCount = {}
        self.timeStamp=0
        self.speed_rec = {}
        self.update_time = self.config.json["update_time"]

        if(self.config.json["enable_monitor"]):
            self.monitor_thread = hub.spawn(self._monitor)

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
        
        self.monitor_dpid = [ self.config.json['sat'][node_name]['datapath']['dpid_d'] if self.check_class(node_name)=='sat' 
                                                    else self.config.json['dc'][node_name]['datapath']['dpid_d'] for node_name in self.config.json["monitor_switch"]]
        
        self.current_time = dt.datetime(year=2020, month=8, day=18, hour=4, minute=40)
        self.last_time = self.current_time
        self.sleepTime = 1.0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.debug("switch_features_handler called!")
        dp = ev.msg.datapath
        self.logger.debug("datapath id is %016d", dp.id)
    
    def install_meter_table(self, dp):
        self.logger.debug("install_meter_table_called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        for i in range(1,10):
            meter_mod = parser.OFPMeterMod(datapath=dp, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=i, bands=[parser.OFPMeterBandDrop(rate=5000, burst_size=0)])
            dp.send_msg(meter_mod)

    def install_to_host_flow_entry(self, dp):
        self.logger.debug("install_to_host_flow_entry called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        host = self.dpid_table[dp.id]
        node_class = self.check_class(host)
        
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=self.config.json[node_class][host]['host']['ip_addr'])
        out_port_num = self.config.json['link_port_num'][host+'_to_host']
        actions = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                                                        [parser.OFPActionOutput(port=out_port_num)])
        inst = [actions]
        self.add_flow(dp, table_id=0, priority=1, match=match, inst=inst)

    def install_pointer_table(self, dp):
        self.logger.debug("install_pointer_table_called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = parser.OFPInstructionGotoTable(self.next_table)
        inst =  [actions]
        self.add_flow(dp, table_id=0, priority=0, match=match, inst=inst)
    
    def install_table_miss_flow_entry(self, dp):
        self.logger.debug("install_table_miss_flow_entry called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                                                        [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                                                                        ofproto.OFPCML_NO_BUFFER)])
        inst = [actions]
        self.add_flow(dp, table_id=1,  priority=0, match=match, inst=inst)
        self.add_flow(dp, table_id=2,  priority=0, match=match, inst=inst)

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
            self.logger.debug("This is ARP")
            self.handle_arp(dp, in_port, pkt)

        if (eth.ethertype == ether_types.ETH_TYPE_IP):
            self.logger.debug("This is packet in message")
            self.handle_ip(dp, ev.msg)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('register datapath: %016d', datapath.id)
                self.datapaths[datapath.id] = datapath

                #clear all old flow tables
                self.clear_all_flow_tables(datapath)
                #clear all meter tables
                self.clear_all_meter_tables(datapath)
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
                self.logger.info('unregister datapath: %016d', datapath.id)
                del self.datapaths[datapath.id]

    def handle_ip(self, dp, msg):
        self.logger.debug("handle_ip called!")
        return
        
    def _monitor(self):
        hub.sleep(10)
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleepTime)

    def _time_simulator(self):
        hub.sleep(30)
        current_time = time.mktime(dt.datetime.now().timetuple())
        while True:
            if time.mktime(dt.datetime.now().timetuple()) - current_time > self.config.json["minutes_interval"]:
                current_time = time.mktime(dt.datetime.now().timetuple()) 
                self.current_time += dt.timedelta(minutes=1)
            hub.sleep(0.5)
    
    def _show_topo(self):
        plt.ion()
        while True:
            virtue_topo.show_topo(self.current_topo)
            hub.sleep(1)
        plt.ioff()
        plt.show()
        
    def _create_topo(self):
        hub.sleep(30)
        self.logger.debug("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.debug("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.debug("The number of datapaths is: %d", len(self.datapaths))
        for key in self.datapaths.keys():
            self.logger.info(key)
        self.logger.debug("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.debug("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        self.logger.debug("_create_topo CALLED  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        while len(self.datapaths) == 7:
            self.logger.info(self.current_time)
            self.logger.info("Start Update!")
            self.current_topo = self.time_expand_topo.slice_topo(self.current_time)
            self.update_meter_table()
            self.update_flow_table()
            self.transfer()
            self.update_pointer_table()
            self.clear_old_flow_table()

            self.last_time = self.current_time
            self.next_table = (3 - pow(-1, self.next_table)) / 2
            hub.sleep(1)
    
    def clear_all_flow_tables(self,datapath):
        self.logger.debug("clear_all_flow_tables called!")
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch()
        for i in range(3):
            req = ofp_parser.OFPFlowMod(datapath, table_id=i, command=ofp.OFPFC_DELETE,
                                                                            match=match,cookie=0, cookie_mask=0,  buffer_id = ofp.OFP_NO_BUFFER,
                                                                            idle_timeout=0, hard_timeout=0,flags=0, out_port=ofp.OFPP_ANY,  
                                                                            out_group=ofp.OFPG_ANY, instructions=[])
            datapath.send_msg(req)
    
    def clear_all_meter_tables(self,dp):
        self.logger.debug("clear_all_meter_tables called!")
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        for i in range(11):
            meter_mod = parser.OFPMeterMod(datapath=dp, command=ofproto.OFPMC_DELETE, flags=ofproto.OFPMF_KBPS, meter_id=i, bands=[parser.OFPMeterBandDrop(rate=10000, burst_size=0)])
            dp.send_msg(meter_mod)

    def install_init_meter_table(self):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
    
            meter_mod = parser.OFPMeterMod(datapath=dp, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=1, bands=[parser.OFPMeterBandDrop(rate=10000, burst_size=0)])
            dp.send_msg(meter_mod)

    def update_meter_table(self):
        for u, v, weight in self.current_topo.edges.data("weight"):
            if weight is not None:
                vel = self.calculate_vel(weight)

                u_class, v_class = self.check_class(u), self.check_class(v)
                u_dpid, v_dpid = self.config.json[u_class][u]["datapath"]["dpid_d"], self.config.json[v_class][v]["datapath"]["dpid_d"]
                u_to_v_port_num, v_to_u_port_num = self.config.json["link_port_num"][u+"_to_"+v], self.config.json["link_port_num"][v+"_to_"+u]
               
                u_dp, v_dp = self.datapaths[u_dpid], self.datapaths[v_dpid]
                u_parser, v_parser = u_dp.ofproto_parser, v_dp.ofproto_parser
                u_ofproto, v_ofproto = u_dp.ofproto, v_dp.ofproto

                u_meter_mod = u_parser.OFPMeterMod(u_dp, command=u_ofproto.OFPMC_MODIFY, flags=u_ofproto.OFPMF_KBPS, meter_id=u_to_v_port_num, bands=[u_parser.OFPMeterBandDrop(rate=vel,burst_size=0)])
                v_meter_mod = v_parser.OFPMeterMod(v_dp, command=v_ofproto.OFPMC_MODIFY, flags=v_ofproto.OFPMF_KBPS, meter_id=v_to_u_port_num, bands=[v_parser.OFPMeterBandDrop(rate=vel,burst_size=0)])
                
                u_dp.send_msg(u_meter_mod)
                v_dp.send_msg(v_meter_mod)

    def transfer(self):
        self.logger.info("TRANSFER CALLED")
        print(self.speed_rec)
        self.logger.info(self.speed_rec['sr1'][self.config.json["link_port_num"]['sr1_to_sr3']])
        self.logger.info("NOT ENTER????????")
        if self.speed_rec['sr1'][self.config.json["link_port_num"]['sr1_to_sr3']] > self.config.json["transfer_threshold"]:
            self.logger.info("ENTER!!!!!!!!!!!!!!!")
            self.logger.info(self.speed_rec['sr1'][self.config.json["link_port_num"]['sr1_to_sr2']] )
            self.logger.info(self.speed_rec['sr1'][self.config.json["link_port_num"]['sr1_to_sr2']] )
            dpid = self.config.json['sat']['sr1']["datapath"]["dpid_d"]
            dp = self.datapaths[dpid]
            ofp = dp.ofproto
            parser = dp.ofproto_parser

            src_ip = self.config.json['sat']['group3']['host']['ip_addr']
            dst_ip = self.config.json['dc']['dc1']['host']['ip_addr']
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=src_ip,ipv4_dst=dst_ip)
            
            out_port_num = self.config.json["link_port_num"]["sr1"+"_to_"+"sr2"]
            meter = parser.OFPInstructionMeter(meter_id=out_port_num)
            actions = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                    [parser.OFPActionOutput(out_port_num)])
            inst = [meter,actions] if self.config.json["meter"] else [actions]
            self.add_flow(dp, table_id=self.next_table, priority=10, match=match,  inst=inst)

    def calculate_vel(self, weight):
        #TODO

        return 10000

    def update_flow_table(self):
        self.all_pairs_shortest_paths = nx.shortest_path(self.current_topo, weight = 'weight')
        print(self.all_pairs_shortest_paths)
        for source in nx.shortest_path(self.current_topo, weight = 'weight'):
            targets_paths = self.all_pairs_shortest_paths[source]
            for target in targets_paths:
                shortest_path = targets_paths[target]
                if len(shortest_path) > 1:
                    self.distribute_flow_table(source, self.next_table, target, shortest_path)
    
    def update_pointer_table(self):
        for datapath in self.datapaths.values():
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            match = ofp_parser.OFPMatch()
            self.logger.debug("Point to table:   %x", self.next_table)
            actions = ofp_parser.OFPInstructionGotoTable(self.next_table)
            inst = [actions]
            req = ofp_parser.OFPFlowMod(datapath, table_id=0, command=ofp.OFPFC_MODIFY_STRICT,
                                                                            match=match,cookie=0, cookie_mask=0,  buffer_id = ofp.OFP_NO_BUFFER,
                                                                            idle_timeout=0, hard_timeout=0,flags=0, out_port=ofp.OFPP_ANY,  priority=0,
                                                                            out_group=ofp.OFPG_ANY, instructions=inst)
            
            datapath.send_msg(req)

    def clear_old_flow_table(self):
        last_table = (3 - pow(-1, self.next_table)) / 2
        for datapath in self.datapaths.values():
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP)
            req = ofp_parser.OFPFlowMod(datapath, table_id=last_table, command=ofp.OFPFC_DELETE,
                                                                            match=match,cookie=0, cookie_mask=0,  buffer_id = ofp.OFP_NO_BUFFER,
                                                                            idle_timeout=0, hard_timeout=0,flags=0, out_port=ofp.OFPP_ANY,  
                                                                            out_group=ofp.OFPG_ANY, instructions=[])
            
            datapath.send_msg(req)

    
    def distribute_flow_table(self, source, next_table, target, shortest_path):
        src_node_class = self.check_class(source)
        dpid = self.config.json[src_node_class][source]["datapath"]["dpid_d"]
        dst_node_class = self.check_class(target)
        dst_ip = self.config.json[dst_node_class][target]["host"]["ip_addr"]

        dp = self.datapaths[dpid]
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        next_hop = shortest_path[1]
        out_port_num = self.config.json["link_port_num"][source+"_to_"+next_hop]

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=dst_ip)
        meter = parser.OFPInstructionMeter(meter_id=out_port_num)
        actions = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [parser.OFPActionOutput(out_port_num)])
        
        inst = [meter,actions] if self.config.json["meter"] else [actions]
        self.add_flow(dp, table_id=next_table, priority=1, match=match,  inst=inst)
    
    def check_class(self, target):
        if 'sr' in target:
            return 'sat'
        if 'group' in target:
            return 'sat'
        if 'dc' in target:
            return 'dc'

    def add_flow(self, datapath, table_id,priority, match, inst, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cookie = cookiemask = 0
        idle_timeout = hard_timeout = 0

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, table_id = table_id, command = ofproto.OFPFC_ADD ,
                                                                    buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id = table_id, command = ofproto.OFPFC_ADD ,
                                                                    priority=priority, match=match, instructions=inst)

        # self.logger.info('Here are flows')
        # self.logger.info(mod)
        datapath.send_msg(mod)        

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        self.logger.debug("_port_stats_reply_handler!")
        body = ev.msg.body
        dp = ev.msg.datapath
        dpid = dp.id
        ofp_parser = dp.ofproto_parser
        self.lastCount.setdefault(dpid, {})

        if dpid in self.monitor_dpid:
            self.logger.info('datapath         port     '
                            'rx-bytes rx-error '
                            'tx-bytes tx-error speed(Mbits/s)')
            self.logger.info('---------------- -------- '
                            '-------- -------- '
                            '-------- -------- -------')
        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no in self.lastCount[dpid]:
                speed = ((stat.rx_bytes + stat.tx_bytes) - self.lastCount[dpid][stat.port_no]) * 8 / (
                            self.sleepTime * 1000000)
            else:
                speed = (stat.rx_bytes + stat.tx_bytes) * 8 / (self.sleepTime * 1000000)

            add_two_dim_dict(self.speed_rec,  self.dpid_table[dpid], stat.port_no, speed)
            if dpid in self.monitor_dpid:
                self.logger.info('%016s %8x %8d %8d %8d %8d %.2f',
                                    self.dpid_table[dpid], stat.port_no,
                                    stat.rx_bytes, stat.rx_errors,
                                    stat.tx_bytes, stat.tx_errors, speed)
            self.lastCount[dpid][stat.port_no] = stat.rx_bytes + stat.tx_bytes

    # PacketOut used to send packet from controller to switch
    def send_packet(self, dp, port, pkt):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port=port)]

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action, data=data)
        dp.send_msg(out)

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

        self.logger.info('ARP REPLYED!')
        self.send_packet(dp, port, pkt)

    # PacketOut used to send packet from controller to switch
