from operator import attrgetter
from utils.utils import check_class

class Monitor:
    def __init__(self,config):
        self._config = config
        self._datapaths = {}
        self.lastCount = {}
        self.monitor_dpid = [ self._config.json['sat'][node_name]['datapath']['dpid'] if check_class(node_name)=='sat' 
                                                    else self._config.json['dc'][node_name]['datapath']['dpid'] for node_name in self._config.json["monitor_switch"]]
        self._current_topo = None
        self._lastCount = {}
        self.next_table = 0
        self.sleep_time = self._config.json['sleep_time']
    
    def _request_stats(self, datapath):
        print('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    def logger(self,ev):
        body = ev.msg.body
        dp = ev.msg.datapath
        dpid = dp.id
        ofp_parser = dp.ofproto_parser
        self._lastCount.setdefault(dpid, {})

        if dpid in self.monitor_dpid:
            print('datapath         port     '
                            'rx-bytes rx-error '
                            'tx-bytes tx-error speed(Mbits/s)')
            print('---------------- -------- '
                            '-------- -------- '
                            '-------- -------- -------')
        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no in self.lastCount[dpid]:
                speed = ((stat.rx_bytes + stat.tx_bytes) - self.lastCount[dpid][stat.port_no]) * 8 / (
                            self.sleep_time * 1000000)
            else:
                speed = (stat.rx_bytes + stat.tx_bytes) * 8 / (self.sleep_time * 1000000)

            if dpid in self.monitor_dpid:
                print('{:016X}{:8x}{:8d}{:8d}{:8d}{:8d}{:.2f}'.format(
                                    dpid, stat.port_no,
                                    stat.rx_bytes, stat.rx_errors,
                                    stat.tx_bytes, stat.tx_errors, speed))
            self.lastCount[dpid][stat.port_no] = stat.rx_bytes + stat.tx_bytes

    @property
    def current_topo(self):
        return self._current_topo

    @current_topo.setter
    def current_topo(self,topo):
        self._current_topo = topo
    

    
        