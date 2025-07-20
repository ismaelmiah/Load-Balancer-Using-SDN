from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet

class FinalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FinalController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.VIRTUAL_IP = '10.0.0.100'
        self.VIRTUAL_MAC = '00:00:00:00:00:FE'
        self.logger.info("--- Final Controller Started ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected. Table-miss rule installed.", datapath.id)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
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

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        # Always learn the source MAC address and its port.
        self.mac_to_port[dpid][eth.src] = in_port

        # --- ARP LOGIC ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info("Received ARP packet: %s", arp_pkt)
            # Check if it's an ARP request for our Virtual IP
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.VIRTUAL_IP:
                self.logger.info("--> This is an ARP for the VIP. Crafting a reply.")
                # Create the ARP reply packet
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.VIRTUAL_MAC))
                reply_pkt.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=self.VIRTUAL_MAC, src_ip=self.VIRTUAL_IP,
                    dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip
                ))
                reply_pkt.serialize()
                
                # Send the ARP reply back out the port it came from
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
                datapath.send_msg(out)
                self.logger.info("--> Sent ARP reply for VIP.")
                return # Stop processing this packet

        # --- L2 SWITCHING LOGIC (for all other packets, including non-VIP ARPs) ---
        self.logger.info("Packet is not a VIP ARP. Treating as L2 traffic. Dst: %s", eth.dst)
        
        if eth.dst in self.mac_to_port[dpid]:
            # If we know the destination, send it to the specific port
            out_port = self.mac_to_port[dpid][eth.dst]
            self.logger.info("--> Destination is known. Port: %s", out_port)
            actions = [parser.OFPActionOutput(out_port)]
            # Install a flow rule to handle this traffic in the switch directly
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions)
        else:
            # If we don't know the destination, flood it
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("--> Destination is unknown. Flooding.")
            actions = [parser.OFPActionOutput(out_port)]

        # Send the packet out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)