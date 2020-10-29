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
from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, icmp, tcp
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.lib import hub

import datetime as dt
import Config
import virtue_topo
import networkx as nx


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.config_path =  '/home/ubuntu/ryu/ryu/app/dsSatellite/config.json'
        self.config = Config.Config(self.config_path)

        self.current_topo = nx.Graph()
        self.time_expand_topo = virtue_topo.create_virtue_topo(self.config)
        self.topo_thread = hub.spawn(self._create_topo)
        self.all_pairs_shortest_paths = {}

        self.monitor_thread = hub.spawn(self._monitor)

        self.arp_table = {self.config.json['sat']['group1']['host']['ip_addr']: self.config.json['sat']['group1']['host']['eth0'],
                          self.config.json['sat']['group2']['host']['ip_addr']: self.config.json['sat']['group2']['host']['eth0'],
                          self.config.json['sat']['group3']['host']['ip_addr']: self.config.json['sat']['group3']['host']['eth0'],
                          self.config.json['sat']['sr1']['host']['ip_addr']: self.config.json['sat']['sr1']['host']['eth0'],
                          self.config.json['sat']['sr2']['host']['ip_addr']: self.config.json['sat']['sr2']['host']['eth0'],
                          self.config.json['sat']['sr3']['host']['ip_addr']: self.config.json['sat']['sr3']['host']['eth0'],
                          self.config.json['dc']['host']['ip_addr']: self.config.json['dc']['host']['eth0']}
        
        self.last_time = dt.datetime(year=2020,month=5,day=8,hour=0,minute=0)

        
        self.mac_to_port = {}
        self.datapaths = {}
        self.lastCount = {}

        self.sleepTime = 1.0
        self.bw = 500
        self.threashold = 0.8

        self.line1 = 0
        self.line2 = 0
        self.timeStamp=0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        if(dp.id == 1):
            self.dp1 = dp
            self.logger.info("dp1 registered")
        if(dp.id == 2):
            self.dp2 = dp
            self.logger.info("dp2 registered")
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        #self.logger.info('Here are flows')
        #self.logger.info(mod)
        datapath.send_msg(mod)

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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("This is ARP")
            self.handle_arp(dp, in_port, pkt)

        if (eth.ethertype == ether_types.ETH_TYPE_IP):
            self.logger.info("This is packet in message")
            #self.logger.info(pkt)
            self.handle_ip(dp, ev.msg)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleepTime)
        
    def _create_topo(self):
        while True:
            current_hour = dt.datetime.now().hour
            current_minute = dt.datetime.now().minute
            if current_hour != self.last_time.hour and current_minute != self.last_time.minute
                self.current_topo = self.time_expand_topo.slice_topo(datetime.datetime.now().hour, datetime.datetime.now().minute)
                self.update_flow_table()
            virtue_topo.show_topo(self.current_topo)
            hub.sleep(self.sleepTime)

    def update_flow_table(self):
        self.all_pairs_shortest_paths = self.current_topo.shortest_path(weight = weight)
        for source in nx.shortest_path(self.current_topo, weight = 'weight'):
            targets_paths = self.all_pairs_shortest_paths[source]
            for target in targets_paths:
                shortest_path = targets_paths[target]
                if len(shortest_path) > 1:
                    self.distribute_flow_table(source, target, shortest_path)
    
    def distribute_flow_table(self, source, target, shortest_path):
        dpid = self.config.json[source]["datapath"]["dpid"]
        dst_ip = self.config.json[target]["host"]["ip_addr"]
        next_hop = shortest_path[1]
        out_port_num = self.config.json["link_port_num"][source+"_to_"+next_hop]
        
        self.logger.info("Here are flows")
        self.logger.info(mod)
    
    def add_flow(self, datapath, priority, match, actions):
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                ofp_parser.OFPActionOutput(out_port))]
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
            datapath.send_msg(mod)

        

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #req = parser.OFPFlowStatsRequest(datapath)
        #datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'ipv4_src ipv4_dst '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- -------- '
                         '-------- -------- --------')

        for stat in sorted([flow for flow in body ],
                           key=lambda flow: (flow.match['ipv4_src'],
                                             flow.match['ipv4_dst'])):
            self.logger.info('%016x %s %s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['ipv4_src'], stat.match['ipv4_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dp = ev.msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        self.lastCount.setdefault(dpid, {})

        self.logger.info('datapath         port     '
                         'rx-bytes rx-error '
                         'tx-bytes tx-error speed(Mb/s)')
        self.logger.info('---------------- -------- '
                         '-------- -------- '
                         '-------- -------- -------')
        f = open('/home/ubuntu/ryu/ryu/app/custom/data.txt', 'a')
        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no in self.lastCount[dpid]:
                speed = ((stat.rx_bytes + stat.tx_bytes) - self.lastCount[dpid][stat.port_no]) * 8 / (
                            self.sleepTime * 1024 * 1024)
            else:
                speed = (stat.rx_bytes + stat.tx_bytes) * 8 / (self.sleepTime * 1024 * 1024)

            if (dpid == 1 and (stat.port_no == 7 or stat.port_no == 8)):
                if (stat.port_no == 7):
                    self.line1 = speed
                else:
                    self.line2 = speed
            if(dpid==1):
                self.timeStamp += 1
                self.logger.info('%016x %8x %8d %8d %8d %8d %.2f',
                                 dpid, stat.port_no,
                                 stat.rx_bytes, stat.rx_errors,
                                 stat.tx_bytes, stat.tx_errors, speed)
                item = "%8d %8x %.2f\n" % (self.timeStamp, stat.port_no, speed)
                f.write(item)
            self.lastCount[dpid][stat.port_no] = stat.rx_bytes + stat.tx_bytes
        f.close()

        # transfer
        if (self.line1 > self.threashold * self.bw):
            for src in self.client.values():
                if (src[1] != "10.0.0.1"):
                    match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=src[1],)
                    self.add_flow(self.dp1, 3, match, actions=[ofp_parser.OFPActionOutput(8)])
                    match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=src[1])
                    self.add_flow(self.dp2, 3, match, actions=[ofp_parser.OFPActionOutput(2)])

    def add_reactive_flow(self, dp, match, table, priority,out_port):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        buffer_id = ofp.OFP_NO_BUFFER

        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(out_port)])
        inst = [action]

        mod = ofp_parser.OFPFlowMod(
            datapath=dp, table_id=table, priority=priority,
            match=match, instructions=inst
        )
        self.logger.info("Here are flows")
        self.logger.info(mod)
        dp.send_msg(mod)

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

        self.send_packet(dp, port, pkt)

    # PacketOut used to send packet from controller to switch

    def handle_ip(self, dp, msg):
        self.logger.info("handle_ip was called")
        pkt = packet.Packet(msg.data)
        #self.logger.info(pkt)

        dp = msg.datapath
        ofproto = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        #ethernet packet
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst

        #ip packet
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_src = ipv4_pkt.src
        ip_dst = ipv4_pkt.dst

        ip_proto = ipv4_pkt.proto  #upper layer protocol will be TCP in our case
        actions = []

        """
        if ip_src == "10.0.0.1" and ip_dst == "10.0.0.3":
            self.logger.info("h1 tooooooooooooo h3")
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst,
                                        ip_proto=ip_proto, in_port=in_port)
            actions.append(ofp_parser.OFPActionOutput(3))
            self.add_flow(self.dp1, 1, match, actions = actions)
            self.add_flow(self.dp2, 1, match, actions = actions)

        if ip_src == "10.0.0.3" and ip_dst == "10.0.0.1":
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst,
                                        ip_proto=ip_proto, in_port=in_port)
            actions.append(ofp_parser.OFPActionOutput(1))
            self.add_flow(self.dp1, 1, match, actions = actions)
            self.add_flow(self.dp2, 1, match, actions = actions)


        if ip_src == "10.0.0.2" and ip_dst == "10.0.0.4":
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst,
                                        ip_proto=ip_proto, in_port=in_port)
            actions.append(ofp_parser.OFPActionOutput(4))
            self.add_flow(self.dp1, 1, match, actions = actions)
            self.add_flow(self.dp2, 1, match, actions = actions)

        if ip_src == "10.0.0.4" and ip_dst == "10.0.0.2":
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst,
                                        ip_proto=ip_proto, in_port=in_port)
            actions.append(ofp_parser.OFPActionOutput(2))
            self.add_flow(self.dp1, 1, match, actions = actions)
            self.add_flow(self.dp2, 1, match, actions = actions)
        """
        if(dp.id==1):
            if(ip_dst in [p[1] for p in self.client.values()]):
                match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ip_dst,
                                            ip_proto=ip_proto, in_port=in_port)
                actions = [ofp_parser.OFPActionOutput(self.client[eth_dst][0])]
                self.add_flow(self.dp1, 1, match, actions=actions )
            else:
                out = 8 if(self.line1>self.line2) else 7
                match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ip_dst,
                                            ip_proto=ip_proto, in_port=in_port)
                actions = [ofp_parser.OFPActionOutput(out)]
                self.add_flow(self.dp1, 1, match, actions=actions)
        else:
            if (ip_dst in [p[1] for p in self.server.values()]):
                match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ip_dst,
                                            ip_proto=ip_proto, in_port=in_port)
                actions = [ofp_parser.OFPActionOutput(self.server[eth_dst][0])]
                self.add_flow(self.dp2, 1, match, actions=actions)
            else:
                out = 2 if (self.line1 > self.line2) else 1
                match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ip_dst,
                                            ip_proto=ip_proto, in_port=in_port)
                actions = [ofp_parser.OFPActionOutput(out)]
                self.add_flow(self.dp2, 1, match, actions=actions)



        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)


