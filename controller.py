from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet, ipv4, tcp
from itertools import cycle # We need cycle for round-robin

class FinalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FinalController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.VIRTUAL_IP = '10.0.0.100'
        self.VIRTUAL_MAC = '00:00:00:00:00:FE'
        
        # --- NEW: Define our real servers ---
        self.server_macs = ['00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04']
        self.server_ips = {mac: f'10.0.0.{int(mac[-1])}' for mac in self.server_macs}
        self.server_iterator = cycle(self.server_macs)
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

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                priority=priority, match=match, instructions=inst)
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
        if not eth: return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.VIRTUAL_IP:
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.VIRTUAL_MAC))
                reply_pkt.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=self.VIRTUAL_MAC, src_ip=self.VIRTUAL_IP,
                    dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip
                ))
                reply_pkt.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
                datapath.send_msg(out)
                return

        # ==============================================================================
        # --- NEW: IP and TCP PACKET HANDLING LOGIC ---
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            # We only load balance TCP packets destined for the VIP
            if tcp_pkt and ipv4_pkt.dst == self.VIRTUAL_IP:
                self.logger.info("Received TCP packet for VIP from %s", ipv4_pkt.src)

                # 1. Select a server using round-robin
                server_mac = next(self.server_iterator)
                server_ip = self.server_ips[server_mac]
                server_out_port = self.mac_to_port[dpid][server_mac]
                self.logger.info("--> Redirecting to server %s (%s) on port %s", server_ip, server_mac, server_out_port)

                # 2. Create flow rule for Client -> Server
                match_forward = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                                                ipv4_src=ipv4_pkt.src, ipv4_dst=self.VIRTUAL_IP,
                                                ip_proto=ipv4_pkt.proto,
                                                tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
                actions_forward = [parser.OFPActionSetField(eth_dst=server_mac),
                                   parser.OFPActionSetField(ipv4_dst=server_ip),
                                   parser.OFPActionOutput(server_out_port)]
                # Add a timeout so the rule is removed after a period of inactivity
                self.add_flow(datapath, 2, match_forward, actions_forward, idle_timeout=10)

                # 3. Create flow rule for Server -> Client (the reverse path)
                match_reverse = parser.OFPMatch(in_port=server_out_port, eth_type=eth.ethertype,
                                                ipv4_src=server_ip, ipv4_dst=ipv4_pkt.src,
                                                ip_proto=ipv4_pkt.proto,
                                                tcp_src=tcp_pkt.dst_port, tcp_dst=tcp_pkt.src_port)
                actions_reverse = [parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC),
                                   parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                                   parser.OFPActionOutput(in_port)]
                self.add_flow(datapath, 2, match_reverse, actions_reverse, idle_timeout=10)

                # 4. Send the current packet along the new path
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions_forward, data=msg.data)
                datapath.send_msg(out)
                return
        # ==============================================================================

        # --- L2 SWITCHING LOGIC (for all other packets) ---
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions, idle_timeout=60)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)