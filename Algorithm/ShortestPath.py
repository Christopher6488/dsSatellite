from Config import Config
from utils.utils import check_class, calculate_vel
from utils.packetout import add_flow
import networkx as nx
from ryu.ofproto import ether, ofproto_v1_3

class ShortestPath:
    def __init__(self, config, monitor):
        self._config = config
        self._current_topo = monitor.current_topo
        self._monitor = monitor
    
    def update_meter_table(self):
        for u, v, weight in self._current_topo.edges.data("weight"):
            if weight is not None:
                vel = calculate_vel(weight)

                u_class, v_class = check_class(u), check_class(v)
                u_dpid, v_dpid = self._config.json[u_class][u]["datapath"]["dpid_d"], self._config.json[v_class][v]["datapath"]["dpid_d"]
                u_to_v_port_num, v_to_u_port_num = self._config.json["link_port_num"][u+"_to_"+v], self._config.json["link_port_num"][v+"_to_"+u]
               
                u_dp, v_dp = self._monitor.datapaths[u_dpid], self._monitor.datapaths[v_dpid]
                u_parser, v_parser = u_dp.ofproto_parser, v_dp.ofproto_parser
                u_ofproto, v_ofproto = u_dp.ofproto, v_dp.ofproto

                u_meter_mod = u_parser.OFPMeterMod(u_dp, command=u_ofproto.OFPMC_MODIFY, flags=u_ofproto.OFPMF_KBPS, meter_id=u_to_v_port_num, bands=[u_parser.OFPMeterBandDrop(rate=vel,burst_size=0)])
                v_meter_mod = v_parser.OFPMeterMod(v_dp, command=v_ofproto.OFPMC_MODIFY, flags=v_ofproto.OFPMF_KBPS, meter_id=v_to_u_port_num, bands=[v_parser.OFPMeterBandDrop(rate=vel,burst_size=0)])
                
                u_dp.send_msg(u_meter_mod)
                v_dp.send_msg(v_meter_mod)
    
    def update_flow_table(self):
        all_pairs_shortest_paths = nx.shortest_path(self.monitor.current_topo, weight = 'weight')
        for source in all_pairs_shortest_paths:
            targets_paths = all_pairs_shortest_paths[source]
            for target in targets_paths:
                shortest_path = targets_paths[target]
                if len(shortest_path) > 1:
                    self.distribute_flow_table(source, self._monitor.next_table, target, shortest_path)
    
    def distribute_flow_table(self, source, next_table, target, shortest_path):
        src_node_class = check_class(source)
        dpid = self._config.json[src_node_class][source]["datapath"]["dpid_d"]
        dst_node_class = check_class(target)
        dst_ip = self._config.json[dst_node_class][target]["host"]["ip_addr"]

        dp = self._monitor.datapaths[dpid]
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        next_hop = shortest_path[1]
        out_port_num = self._config.json["link_port_num"][source+"_to_"+next_hop]

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=dst_ip)
        meter = parser.OFPInstructionMeter(meter_id=out_port_num)
        actions = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                    [parser.OFPActionOutput(out_port_num)])

        inst = [meter,actions] if self._config.json["meter"] else [actions]
        add_flow(dp, table_id=next_table, priority=1, match=match,  inst=inst) 

    def clear_old_flow_table(self):
        last_table = (3 - pow(-1, self._monitor.next_table)) / 2
        for datapath in self._monitor.datapaths.values():
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP)
            req = ofp_parser.OFPFlowMod(datapath, table_id=last_table, command=ofp.OFPFC_DELETE,
                                                                            match=match,cookie=0, cookie_mask=0,  buffer_id = ofp.OFP_NO_BUFFER,
                                                                            idle_timeout=0, hard_timeout=0,flags=0, out_port=ofp.OFPP_ANY,  
                                                                            out_group=ofp.OFPG_ANY, instructions=[])
            
            datapath.send_msg(req) 

    def update_pointer_table(self):
        for datapath in self._monitor.datapaths.values():
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            match = ofp_parser.OFPMatch()
            print("Point to table:   %d"%self._monitor.next_table)
            actions = ofp_parser.OFPInstructionGotoTable(self._monitor.next_table)
            inst = [actions]
            req = ofp_parser.OFPFlowMod(datapath, table_id=0, command=ofp.OFPFC_MODIFY_STRICT,
                                                                            match=match,cookie=0, cookie_mask=0,  buffer_id = ofp.OFP_NO_BUFFER,
                                                                            idle_timeout=0, hard_timeout=0,flags=0, out_port=ofp.OFPP_ANY,  priority=0,
                                                                            out_group=ofp.OFPG_ANY, instructions=inst)
            
            datapath.send_msg(req)
