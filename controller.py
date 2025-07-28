# controller.py - The Complete, Working Load Balancer

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet, ipv4, tcp
from itertools import cycle

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.VIRTUAL_IP = '10.0.0.100'
        self.VIRTUAL_MAC = '00:00:00:00:00:FE'
        
        self.server_macs = ['00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04']
        self.server_ips = {mac: f'10.0.0.{int(mac[-1])}' for mac in self.server_macs}
        self.server_iterator = cycle(self.server_macs)
        self.logger.info("--- Load Balancer Application Started ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
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

        if not eth: return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # --- Handle Special VIP ARP Requests ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.VIRTUAL_IP:
            self.logger.info("ARP for VIP received. Replying.")
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.VIRTUAL_MAC))
            reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.VIRTUAL_MAC, src_ip=self.VIRTUAL_IP, dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
            reply_pkt.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
            datapath.send_msg(out)
            return

        # --- Handle Special VIP TCP Traffic ---
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt and ipv4_pkt.dst == self.VIRTUAL_IP:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                self.logger.info("TCP for VIP received. Load Balancing.")
                # Select a server
                server_mac = next(self.server_iterator)
                server_ip = self.server_ips[server_mac]
                self.logger.info("--> Round-robin selected server: %s", server_ip)
                # Make sure we know where the chosen server is before proceeding
                if server_mac in self.mac_to_port[dpid]:
                    server_out_port = self.mac_to_port[dpid][server_mac]
                    
                    # Install Forwarding Rule (Client -> Server)
                    match_forward = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, ipv4_src=ipv4_pkt.src, ipv4_dst=self.VIRTUAL_IP, ip_proto=ipv4_pkt.proto, tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
                    actions_forward = [parser.OFPActionSetField(eth_dst=server_mac), parser.OFPActionSetField(ipv4_dst=server_ip), parser.OFPActionOutput(server_out_port)]
                    self.add_flow(datapath, 2, match_forward, actions_forward, idle_timeout=10)
                    
                    # Install Reverse Rule (Server -> Client)
                    match_reverse = parser.OFPMatch(in_port=server_out_port, eth_type=eth.ethertype, ipv4_src=server_ip, ipv4_dst=ipv4_pkt.src, ip_proto=ipv4_pkt.proto, tcp_src=tcp_pkt.dst_port, tcp_dst=tcp_pkt.src_port)
                    actions_reverse = [parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC), parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP), parser.OFPActionOutput(in_port)]
                    self.add_flow(datapath, 2, match_reverse, actions_reverse, idle_timeout=10)
                    
                    # Send the current packet out
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions_forward, data=msg.data)
                    datapath.send_msg(out)
                else:
                    self.logger.warning("Server %s port not learned yet. Dropping packet.", server_mac)
                return
        
        # --- Handle all other traffic as a standard L2 Switch ---
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions, idle_timeout=60)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)