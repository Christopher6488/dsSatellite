from utils.utils import check_class

def request_stats(self, datapath):
    print('send stats request:{:016X}'.format(datapath.id))
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
    datapath.send_msg(req)

def add_flow(datapath, table_id,priority, match, inst, buffer_id=None):
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

def clear_all_flow_tables(datapath):
    print("clear_all_flow_tables called!")
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser
    match = ofp_parser.OFPMatch()
    for i in range(3):
        req = ofp_parser.OFPFlowMod(datapath, table_id=i, command=ofp.OFPFC_DELETE,
                                                                        match=match,cookie=0, cookie_mask=0,  buffer_id = ofp.OFP_NO_BUFFER,
                                                                        idle_timeout=0, hard_timeout=0,flags=0, out_port=ofp.OFPP_ANY,  
                                                                        out_group=ofp.OFPG_ANY, instructions=[])
        datapath.send_msg(req)

def clear_all_meter_tables(dp):
    print("clear_all_meter_tables called!")
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    for i in range(11):
        meter_mod = parser.OFPMeterMod(datapath=dp, command=ofproto.OFPMC_DELETE, flags=ofproto.OFPMF_KBPS, meter_id=i, bands=[parser.OFPMeterBandDrop(rate=10000, burst_size=0)])
        dp.send_msg(meter_mod)

# PacketOut used to send packet from controller to switch
def send_packet(dp, port, pkt):
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
