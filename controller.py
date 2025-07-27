# controller.py - The Ultimate Diagnostic Logger Switch

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp

class LoggerSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoggerSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.logger.info("--- Diagnostic Logger Switch Started ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]))
        self.logger.info("Switch %s connected. Table-miss rule installed.", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth:
            return

        self.logger.info("="*50)
        self.logger.info("PACKET-IN on Switch %s from Port %s", datapath.id, in_port)
        self.logger.info("--- ETH: %s -> %s", eth.src, eth.dst)

        # Log packet details
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info("--- ARP: %s -> %s (Op: %s)", arp_pkt.src_ip, arp_pkt.dst_ip, arp_pkt.opcode)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self.logger.info("--- IP:  %s -> %s (Proto: %s)", ipv4_pkt.src, ipv4_pkt.dst, ipv4_pkt.proto)

        # Always learn the source MAC
        self.mac_to_port[datapath.id] = self.mac_to_port.get(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        self.logger.info("Learning: MAC %s is on Port %s", eth.src, in_port)
        
        # --- L2 Forwarding Decision ---
        if eth.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth.dst]
            self.logger.info("Decision: Destination %s is KNOWN. Forwarding to port %s.", eth.dst, out_port)
            actions = [parser.OFPActionOutput(out_port)]
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("Decision: Destination %s is UNKNOWN. Flooding.", eth.dst)
            actions = [parser.OFPActionOutput(out_port)]
        
        # --- Send the PacketOut message ---
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
        self.logger.info("Action: Sent PacketOut message.")
        self.logger.info("="*50)