# controller.py - Corrected Logic Flow

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp

class FinalWorkingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FinalWorkingController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # --- ADDED FOR THE NEXT STEP ---
        self.VIRTUAL_IP = '10.0.0.100'
        self.VIRTUAL_MAC = '00:00:00:00:00:FE'
        self.logger.info("--- Corrected Controller Started ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]))
        self.logger.info("Switch %s connected.", datapath.id)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)


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

        # Always learn the source MAC
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # --- CORRECTED LOGIC FLOW ---
        arp_pkt = pkt.get_protocol(arp.arp)
        
        # Is it an ARP packet?
        if arp_pkt:
            # Is it an ARP request for our VIP?
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.VIRTUAL_IP:
                self.logger.info("ARP for VIP received. Replying.")
                # Create and send a custom ARP reply
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.VIRTUAL_MAC))
                reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.VIRTUAL_MAC, src_ip=self.VIRTUAL_IP, dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
                reply_pkt.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
                datapath.send_msg(out)
                return # We are done with this packet, so exit the function
            # If it's any other ARP packet, it will fall through to the L2 logic below.
        
        # --- If it's not a special ARP, treat it as L2 traffic ---
        self.logger.info("Forwarding as standard L2 traffic.")
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            actions = [parser.OFPActionOutput(out_port)]
            # Install a flow rule for this conversation
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions, idle_timeout=60)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)