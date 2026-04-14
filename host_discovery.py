from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
import datetime

BLOCKED_MAC = "00:00:00:00:00:04"

class HostDiscovery(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HostDiscovery, self).__init__(*args, **kwargs)
        self.host_db = {}
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("=== Host Discovery Service Started ===")
        self.logger.info("Blocked MAC: %s" % BLOCKED_MAC)

    # ======= FLOW INSTALL =======
    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst)
        datapath.send_msg(mod)

    # ======= SWITCH CONNECT =======
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("[SWITCH CONNECTED] DPID=%s", datapath.id)

    # ======= TRACK DATAPATHS FOR MONITORING =======
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("[MONITOR] Tracking switch DPID=%s", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    # ======= MONITORING THREAD =======
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(15)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # ======= FLOW STATS REPLY =======
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.logger.info("\n========== [FLOW STATS] Switch=%s ==========",
                         ev.msg.datapath.id)
        self.logger.info("%-10s %-20s %-10s %-10s" %
                         ("Priority", "Match", "Packets", "Bytes"))
        self.logger.info("-" * 60)
        for stat in sorted(ev.msg.body, key=lambda s: s.priority, reverse=True):
            self.logger.info("%-10s %-20s %-10s %-10s" % (
                stat.priority,
                str(stat.match),
                stat.packet_count,
                stat.byte_count))

    # ======= MAIN PACKET HANDLER =======
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return
        if eth.ethertype == 0x88cc:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # ======= FIREWALL =======
        if src_mac == BLOCKED_MAC:
            self.logger.info("==========================================")
            self.logger.info("[FIREWALL] BLOCKING MAC: %s", src_mac)
            self.logger.info("==========================================")
            match = parser.OFPMatch(eth_src=src_mac)
            self.add_flow(datapath, priority=100, match=match, actions=[],
                          idle_timeout=0, hard_timeout=0)
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=[],
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
            datapath.send_msg(out)
            return

        # ======= MAC LEARNING =======
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # ======= GET IP =======
        src_ip = None
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt:
            src_ip = arp_pkt.src_ip
        elif ip_pkt:
            src_ip = ip_pkt.src

        now = datetime.datetime.now().strftime("%H:%M:%S")

        # ======= HOST DISCOVERY =======
        if src_mac not in self.host_db:
            self.host_db[src_mac] = {
                'ip': src_ip, 'dpid': dpid, 'port': in_port,
                'first_seen': now, 'last_seen': now
            }
            self.logger.info("[NEW HOST] MAC=%s IP=%s Switch=%s Port=%s",
                             src_mac, src_ip, dpid, in_port)
        else:
            self.host_db[src_mac]['last_seen'] = now

        # ======= FORWARDING =======
        if dst_mac in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        # ======= PACKET OUT =======
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=None)
        else:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data)
        datapath.send_msg(out)
