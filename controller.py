from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, tcp, icmp
from pox.lib.addresses import IPAddr, EthAddr
import time
import logging
import os
import logging


log_file = os.path.expanduser('~/pox/pox/controller.log')
if os.path.exists(log_file):
    os.remove(log_file) 

file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
log = core.getLogger()  # Get root logger
log.addHandler(file_handler)
log.setLevel(logging.INFO)

class Rule:
    def __init__(self, src=None, dst=None, proto=None, port=None, action='block'):
        # all parameters are strings or ints, or None for “any”
        self.src   = src     # e.g. '10.0.0.100'
        self.dst   = dst     # e.g. '10.0.0.10'
        self.proto = proto   # 'tcp', 'icmp', or 'arp'
        self.port  = port    # integer or None
        self.action = action # 'block' or 'allow'

    def matches(self, src_ip, dst_ip, proto, dst_port):
        return ((self.src   is None or src_ip == self.src) and
                (self.dst   is None or dst_ip == self.dst) and
                (self.proto is None or proto   == self.proto) and
                (self.port  is None or dst_port == self.port))

class Security_Controller(object):
    def __init__(self, connection):
        self.cowrie_ip = "10.0.0.200"  
        self.redirect_ports = [22, 23]
        self.cowrie_ssh_port = 2222      # Cowrie’s actual SSH port
        self.cowrie_telnet_port = 2223   # same for telent
        self.mac_to_port = {}  # Track MAC addresses and their ports
        self.connection = connection
       
        self.deny_rules = [
            Rule(src='10.0.0.100',           action='block'),  # any from h100
            Rule(src='10.0.0.100', dst='10.0.0.10', proto='icmp', action='block'),
            Rule(dst='10.0.0.10', proto='tcp',  port=80,   action='block'),
        ]

        self.allow_rules = [
            # --- Essential Network Services ---
            # Allow ARP for local address resolution and ICMP for ping/debugging.
            Rule(proto='arp', action='allow'),
            Rule(proto='icmp', action='allow'),
            Rule(proto='tcp', port=53, action='allow'),
            Rule(proto='udp', port=53, action='allow'),
            Rule(src='10.0.0.6', action='allow'),
            Rule(dst='10.0.0.6', action='allow'),
            


	    Rule(dst='10.0.0.50', proto='tcp', port=5000, action='allow'), 
	    Rule(src='10.0.0.50', proto='tcp', action='allow'),
            


        # --- Legitimate Server Traffic ---
            # Allow HTTPS traffic to the main server.
            Rule(dst='10.0.0.10', proto='tcp', port=443, action='allow'),
            # Allow the main server to send replies back.
            Rule(src='10.0.0.10', proto='tcp', action='allow'),
            
            # --- Honeypot Traffic ---
            # Allow the honeypot to send replies back to attackers.
            Rule(src=self.cowrie_ip, proto='tcp', action='allow'),
            # Allow redirected traffic to reach the honeypot's internal SSH/Telnet ports.
            Rule(dst=self.cowrie_ip, proto='tcp', port=2222, action='allow'),
            Rule(dst=self.cowrie_ip, proto='tcp', port=2223, action='allow')
        ]
        self._last_blocked = {}
        self.ip_packet_count = {}
        self.block_threshold = 100
        self.block_duration = 60
        connection.addListeners(self)
        log.info(f"Security on switch {connection.dpid} is ACTIVE")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        eth = packet.find('ethernet')
        ip_header = packet.find('ipv4')
        tcp_header = packet.find('tcp')
        icmp_header = packet.find('icmp')

        # 🧠 Always learn MAC to port mapping early
        self.mac_to_port[eth.src.toStr()] = event.port

        
        # Redirect to Cowrie for SSH/TELNET and RETURN
        if tcp_header and tcp_header.dstport in self.redirect_ports:
            self._redirect_to_cowrie(event)
            return  # Exit after redirect

        # Extract IP/port info
        src_ip = str(ip_header.srcip) if ip_header else None
        dst_ip = str(ip_header.dstip) if ip_header else None
        protocol = 'tcp' if tcp_header else 'icmp' if icmp_header else 'arp'
        dst_port = tcp_header.dstport if tcp_header else None

        # Validate firewall rules FIRST
        action = self._validate_rule(src_ip, dst_ip, protocol, dst_port)
        if action == 'block':
            self._enforce_block(packet)
            return  # Drop packet

        # Handle ARP separately (flood requests)
        if protocol == 'arp':
            # Learn MAC address <-> port mapping
            self.mac_to_port[eth.src.toStr()] = event.port

            # Flood ARP request
            packet_out = of.ofp_packet_out(data=event.ofp.data)
            packet_out.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.connection.send(packet_out)
            return

        # For non-ARP packets, find output port using MAC table
        dst_mac = eth.dst.toStr()
        if dst_mac in self.mac_to_port:
            out_port = self.mac_to_port[dst_mac]
        else:
            out_port = of.OFPP_FLOOD  # Flood if unknown


        # install a flow to allow similar packets:
        match = of.ofp_match.from_packet(packet)
        flow_msg = of.ofp_flow_mod(match=match, idle_timeout=10)
        flow_msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(flow_msg)

        # Forward current packet
        packet_out = of.ofp_packet_out(data=event.ofp.data)
        packet_out.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(packet_out)


        # Check for SYN floods (only if allowed by rules)
        if protocol == 'tcp' and tcp_header.SYN:
            self._check_SYN_flood(src_ip,dst_ip)

    def _install_syn_block_flow(self, src_ip):
        try:
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=IPAddr(src_ip))
            msg.priority = of.OFP_DEFAULT_PRIORITY + 1000
            msg.idle_timeout = 0
            msg.hard_timeout = 0
            msg.actions = []  # Drop
            self.connection.send(msg)

            # Add a permanent rule to deny list
            if not any(r.src == src_ip for r in self.deny_rules):
                self.deny_rules.append(Rule(src=src_ip, action='block'))

            # Log once
            current_time = time.time()
            last_blocked = self._last_blocked.get(src_ip, 0)
            if current_time - last_blocked >= 5:
                log.warning(f"PERMANENT block for SYN attacker {src_ip}")
                self._last_blocked[src_ip] = current_time

            if src_ip in self.ip_packet_count:
                del self.ip_packet_count[src_ip]

        except Exception as e:
            log.error(f"Flow install error for {src_ip}: {e}")



    def _check_SYN_flood(self, src_ip, dst_ip):
        # Only detect SYN floods targeting the server
        if dst_ip != "10.0.0.10":
            return
        timeout_window = 10
        current_time = time.time()
        tracker = self.ip_packet_count.get(src_ip, {'count': 0, 'last': 0})
        
        if current_time - tracker['last'] < timeout_window:
            tracker['count'] += 1
            if tracker['count'] >= self.block_threshold:
                self._install_syn_block_flow(src_ip)
                return  # Stop counting after blocking
        else:
            tracker = {'count': 1, 'last': current_time}
        
        self.ip_packet_count[src_ip] = tracker
    


    def _validate_rule(self, src_ip, dst_ip, protocol, dst_port):
        # 1) Deny overrides everything
        for rule in self.deny_rules:
            if rule.matches(src_ip, dst_ip, protocol, dst_port):              
                return 'block'
        # 2) Then allow
        for rule in self.allow_rules:
            if rule.matches(src_ip, dst_ip, protocol, dst_port):
                return 'allow'
        # 3) Default: block
        log.debug("Firewall: DENY by default")
        return 'allow'


    def _redirect_to_cowrie(self, event):
        packet = event.parsed
        ip_header = packet.find('ipv4')
        
        # 🧯 Avoid redirect loop
        if ip_header and ip_header.srcip == self.cowrie_ip:
            return

        
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        

        cowrie_ip = IPAddr(self.cowrie_ip)
        cowrie_mac = EthAddr("00:00:00:00:00:20")
        server_mac = EthAddr("00:00:00:00:00:10")
        cowrie_port = self.mac_to_port.get(cowrie_mac.toStr(), of.OFPP_FLOOD)

        original_ip = packet.find('ipv4')
        original_eth = packet.find('ethernet')
        tcp_seg = packet.find('tcp')

        if not (original_ip and tcp_seg):
            return

        if tcp_seg.dstport == 22:
            new_port = 2222
        elif tcp_seg.dstport == 23:
            new_port = 2223
        else:
            return

        actions = [
            # ONLY modify destination fields (leave source as original client)
        of.ofp_action_nw_addr(type=of.OFPAT_SET_NW_DST, nw_addr=cowrie_ip),
        of.ofp_action_dl_addr(type=of.OFPAT_SET_DL_DST, dl_addr=cowrie_mac),
        of.ofp_action_tp_port(type=of.OFPAT_SET_TP_DST, tp_port=new_port),
        # REMOVE source modification actions (problematic lines deleted)
        of.ofp_action_output(port=cowrie_port)
        ]
        # FORWARD INITIAL PACKET:
        po = of.ofp_packet_out(in_port=event.port, data=event.ofp)
        po.actions = actions
        self.connection.send(po)


        msg.actions = actions
        msg.idle_timeout = 30
        self.connection.send(msg)

        # install reverse flow
        reverse = of.ofp_flow_mod()
        reverse.match.dl_type = ethernet.IP_TYPE
        reverse.match.nw_proto = 6  # TCP
        reverse.match.nw_src = cowrie_ip
        reverse.match.nw_dst = original_ip.srcip
        reverse.match.tp_src = new_port
        reverse.match.tp_dst = tcp_seg.srcport
        reverse.actions.append(of.ofp_action_nw_addr(type=of.OFPAT_SET_NW_SRC, nw_addr=original_ip.dstip))
        reverse.actions.append(of.ofp_action_dl_addr(type=of.OFPAT_SET_DL_SRC, dl_addr=server_mac))
        reverse.actions.append(of.ofp_action_tp_port(type=of.OFPAT_SET_TP_SRC, tp_port=22))
        reverse.actions.append(of.ofp_action_nw_addr(type=of.OFPAT_SET_NW_DST, nw_addr=original_ip.srcip))
        reverse.actions.append(of.ofp_action_dl_addr(type=of.OFPAT_SET_DL_DST, dl_addr=original_eth.src))
        reverse.actions.append(of.ofp_action_tp_port(type=of.OFPAT_SET_TP_DST, tp_port=tcp_seg.srcport))
        reverse.actions.append(of.ofp_action_output(port=self.mac_to_port.get(original_eth.src.toStr(), of.OFPP_FLOOD)))
        reverse.idle_timeout = 30
        self.connection.send(reverse)

        log.info(f"Redirected traffic to Cowrie from : {original_ip.srcip} ")
        

    def _enforce_block(self, packet):
        """Install flow to block malicious traffic."""
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 60  # Block for 60 seconds
        self.connection.send(msg)

def launch():
    logging.getLogger("packet").setLevel(logging.CRITICAL)
    core.openflow.addListenerByName("ConnectionUp", lambda event: Security_Controller(event.connection))
