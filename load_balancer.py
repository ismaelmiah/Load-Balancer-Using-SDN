# controller.py - The Final Adaptive Load Balancer

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet, ipv4, tcp
from ryu.lib import hub # Required for background threads

import requests # Required to make HTTP requests
import json
import random # To select a random server from the active ones

class AdaptiveLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AdaptiveLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.VIRTUAL_IP = '10.0.0.100'
        self.VIRTUAL_MAC = '00:00:00:00:00:FE'
        
        # --- NEW: A more advanced data structure for servers ---
        # We now track IP, MAC, and health status for each server
        self.servers = [
            {'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02', 'health': 'HEALTHY', 'cpu': 0},
            {'ip': '10.0.0.3', 'mac': '00:00:00:00:00:03', 'health': 'HEALTHY', 'cpu': 0},
            {'ip': '10.0.0.4', 'mac': '00:00:00:00:00:04', 'health': 'HEALTHY', 'cpu': 0},
        ]
        
        # --- NEW: Start a background thread for monitoring ---
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("--- Adaptive Load Balancer Application Started ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # ... (This function is the same as before) ...
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected.", datapath.id)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        # ... (This function is the same as before) ...
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)
        
    # --- NEW: The monitoring function that runs in the background ---
    def _monitor(self):
        self.logger.info("Starting server health monitor...")
        while True:
            for server in self.servers:
                try:
                    # Poll the server's /metrics endpoint
                    response = requests.get(f"http://{server['ip']}:5000/metrics", timeout=1)
                    if response.status_code == 200:
                        # --- ADD THIS BLOCK ---
                        if server['health'] == 'DOWN':
                            self.logger.info(f"SERVER RECOVERED (was down): {server['ip']}. Reactivating.")
                        # --- END ADDED BLOCK ---
                        
                        metrics = response.json()
                        server['cpu'] = metrics.get('cpu_percent', 100)
                        
                        # The Adaptive Logic
                        if server['cpu'] > 80 and server['health'] == 'HEALTHY':
                            server['health'] = 'OVERLOADED'
                            self.logger.warning(f"SERVER OVERLOADED: {server['ip']} at {server['cpu']}% CPU. Deactivating.")
                        elif server['cpu'] < 50 and server['health'] == 'OVERLOADED':
                            server['health'] = 'HEALTHY'
                            self.logger.info(f"SERVER RECOVERED (from load): {server['ip']} at {server['cpu']}% CPU. Reactivating.")

                        # --- If it's not overloaded, make sure it's marked healthy ---
                        if server['health'] != 'OVERLOADED':
                            server['health'] = 'HEALTHY'
                            
                except requests.exceptions.RequestException:
                    # If we can't connect, mark it as down
                    if server['health'] != 'DOWN':
                        server['health'] = 'DOWN'
                        self.logger.error(f"SERVER DOWN: Cannot connect to {server['ip']}. Deactivating.")
            
            # Print a status line
            active_servers = [s['ip'] for s in self.servers if s['health'] == 'HEALTHY']
            self.logger.info(f"Monitor status: Active Servers = {active_servers}")
            
            # Wait for 5 seconds before checking again
            hub.sleep(5)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # ... (The first part of this function is the same) ...
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

        # --- Handle Special VIP ARP Requests (same as before) ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.VIRTUAL_IP:
            # ... (code is identical to before, omitted for brevity) ...
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.VIRTUAL_MAC))
            reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.VIRTUAL_MAC, src_ip=self.VIRTUAL_IP, dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
            reply_pkt.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
            datapath.send_msg(out)
            return

        # --- MODIFIED: Handle Special VIP TCP Traffic ---
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt and ipv4_pkt.dst == self.VIRTUAL_IP:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                # --- NEW: Select from ACTIVE servers only ---
                active_servers = [s for s in self.servers if s['health'] == 'HEALTHY']
                if not active_servers:
                    self.logger.error("No active servers available to handle request!")
                    return

                # Select a random server from the active list
                server = random.choice(active_servers)
                self.logger.info(f"TCP for VIP received. Redirecting to active server: {server['ip']}")
                
                # --- The rest of the logic is the same, using the 'server' object ---
                if server['mac'] in self.mac_to_port[dpid]:
                    server_out_port = self.mac_to_port[dpid][server['mac']]
                    match_forward = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, ipv4_src=ipv4_pkt.src, ipv4_dst=self.VIRTUAL_IP, ip_proto=ipv4_pkt.proto, tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
                    actions_forward = [parser.OFPActionSetField(eth_dst=server['mac']), parser.OFPActionSetField(ipv4_dst=server['ip']), parser.OFPActionOutput(server_out_port)]
                    self.add_flow(datapath, 2, match_forward, actions_forward, idle_timeout=10)
                    match_reverse = parser.OFPMatch(in_port=server_out_port, eth_type=eth.ethertype, ipv4_src=server['ip'], ipv4_dst=ipv4_pkt.src, ip_proto=ipv4_pkt.proto, tcp_src=tcp_pkt.dst_port, tcp_dst=tcp_pkt.src_port)
                    actions_reverse = [parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC), parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP), parser.OFPActionOutput(in_port)]
                    self.add_flow(datapath, 2, match_reverse, actions_reverse, idle_timeout=10)
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions_forward, data=msg.data)
                    datapath.send_msg(out)
                else:
                    self.logger.warning("Server %s port not learned yet. Dropping packet.", server['mac'])
                return
        
        # --- Handle all other traffic as a standard L2 Switch (same as before) ---
        if eth.dst in self.mac_to_port[dpid]:
            # ... (code is identical to before, omitted for brevity) ...
            out_port = self.mac_to_port[dpid][eth.dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions, idle_timeout=60)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)