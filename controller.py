from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, tcp, udp, icmp
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
        self.src   = src
        self.dst   = dst
        self.proto = proto
        self.port  = port
        self.action = action

    def matches(self, src_ip, dst_ip, proto, dst_port):
        return ((self.src   is None or src_ip == self.src) and
                (self.dst   is None or dst_ip == self.dst) and
                (self.proto is None or proto   == self.proto) and
                (self.port  is None or dst_port == self.port))

class Security_Controller(object):
    def __init__(self, connection):
        self.cowrie_ip = "10.0.0.200"  
        self.redirect_ports = [22, 23]
        self.cowrie_ssh_port = 2222
        self.cowrie_telnet_port = 2223
        self.mac_to_port = {}
        self.connection = connection

        self.deny_rules = [
            Rule(src='10.0.0.100',           action='block'),
            Rule(src='10.0.0.100', dst='10.0.0.10', proto='icmp', action='block'),
            Rule(dst='10.0.0.10', proto='tcp',  port=80,   action='block'),
        ]

        self.allow_rules = [
            Rule(proto='arp', action='allow'),
            Rule(proto='icmp', action='allow'),
            Rule(proto='tcp', port=53, action='allow'),
            Rule(proto='udp', port=53, action='allow'),
            Rule(src='10.0.0.6', action='allow'),
            Rule(dst='10.0.0.6', action='allow'),
            Rule(dst='10.0.0.50', proto='tcp', port=5000, action='allow'), 
            Rule(src='10.0.0.50', proto='tcp', action='allow'),
            Rule(dst='10.0.0.10', proto='tcp', port=443, action='allow'),
            Rule(src='10.0.0.10', proto='tcp', action='allow'),
            Rule(src=self.cowrie_ip, proto='tcp', action='allow'),
            Rule(dst=self.cowrie_ip, proto='tcp', port=2222, action='allow'),
            Rule(dst=self.cowrie_ip, proto='tcp', port=2223, action='allow')
        ]

        self._last_blocked = {}
        self.ip_packet_count = {}
        self.block_threshold = 100
        self.block_duration = 60

        self.port_scan_tracker = {}
        self.port_scan_threshold = 10
        self.port_scan_window = 5
        self.port_scan_block_time = 60

        connection.addListeners(self)
        log.info(f"Security on switch {connection.dpid} is ACTIVE")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        eth = packet.find('ethernet')
        ip_header = packet.find('ipv4')
        tcp_header = packet.find('tcp')
        udp_header = packet.find('udp')
        icmp_header = packet.find('icmp')

        self.mac_to_port[eth.src.toStr()] = event.port

        if tcp_header and tcp_header.dstport in self.redirect_ports:
            self._redirect_to_cowrie(event)
            return

        src_ip = str(ip_header.srcip) if ip_header else None
        dst_ip = str(ip_header.dstip) if ip_header else None
        protocol = 'tcp' if tcp_header else 'udp' if udp_header else 'icmp' if icmp_header else 'arp'
        dst_port = tcp_header.dstport if tcp_header else udp_header.dstport if udp_header else None

        action = self._validate_rule(src_ip, dst_ip, protocol, dst_port)
        if action == 'block':
            self._enforce_block(packet)
            return

        if protocol == 'arp':
            self.mac_to_port[eth.src.toStr()] = event.port
            packet_out = of.ofp_packet_out(data=event.ofp.data)
            packet_out.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.connection.send(packet_out)
            return

        dst_mac = eth.dst.toStr()
        out_port = self.mac_to_port.get(dst_mac, of.OFPP_FLOOD)

        match = of.ofp_match.from_packet(packet)
        flow_msg = of.ofp_flow_mod(match=match, idle_timeout=10)
        flow_msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(flow_msg)

        packet_out = of.ofp_packet_out(data=event.ofp.data)
        packet_out.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(packet_out)

        if protocol == 'tcp' and tcp_header.SYN:
            self._check_SYN_flood(src_ip, dst_ip)

        if protocol in ('tcp', 'udp') and dst_port is not None:
            self._check_port_scan(src_ip, dst_port)

    def _check_port_scan(self, src_ip, dst_port):
        current_time = time.time()
        tracker = self.port_scan_tracker.get(src_ip, {'ports': set(), 'start': current_time})

        if current_time - tracker['start'] < self.port_scan_window:
            tracker['ports'].add(dst_port)
            if len(tracker['ports']) >= self.port_scan_threshold:
                self._install_portscan_block_flow(src_ip)
                del self.port_scan_tracker[src_ip]
        else:
            tracker = {'ports': {dst_port}, 'start': current_time}

        self.port_scan_tracker[src_ip] = tracker

    def _install_portscan_block_flow(self, src_ip):
        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = IPAddr(src_ip)
        msg.idle_timeout = self.port_scan_block_time
        msg.actions = []
        self.connection.send(msg)
        log.warning(f"Blocked port scanner {src_ip} for {self.port_scan_block_time} sec")

        
    def _install_syn_block_flow(self, src_ip):
        try:
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=IPAddr(src_ip))
            msg.priority = of.OFP_DEFAULT_PRIORITY + 1000
            msg.idle_timeout = 0
            msg.hard_timeout = 0
            msg.actions = []  
            self.connection.send(msg)

            
            if not any(r.src == src_ip for r in self.deny_rules):
                self.deny_rules.append(Rule(src=src_ip, action='block'))

            
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
        if dst_ip != "10.0.0.10":
            return
        timeout_window = 10
        current_time = time.time()
        tracker = self.ip_packet_count.get(src_ip, {'count': 0, 'last': 0})
        
        if current_time - tracker['last'] < timeout_window:
            tracker['count'] += 1
            if tracker['count'] >= self.block_threshold:
                self._install_syn_block_flow(src_ip)
                return  
        else:
            tracker = {'count': 1, 'last': current_time}
        
        self.ip_packet_count[src_ip] = tracker
    


    def _validate_rule(self, src_ip, dst_ip, protocol, dst_port):
        for rule in self.deny_rules:
            if rule.matches(src_ip, dst_ip, protocol, dst_port):              
                return 'block'
        for rule in self.allow_rules:
            if rule.matches(src_ip, dst_ip, protocol, dst_port):
                return 'allow'
        log.debug("Firewall: DENY by default")
        return 'allow'


    def _redirect_to_cowrie(self, event):
        packet = event.parsed
        ip_header = packet.find('ipv4')
        
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
            
        of.ofp_action_nw_addr(type=of.OFPAT_SET_NW_DST, nw_addr=cowrie_ip),
        of.ofp_action_dl_addr(type=of.OFPAT_SET_DL_DST, dl_addr=cowrie_mac),
        of.ofp_action_tp_port(type=of.OFPAT_SET_TP_DST, tp_port=new_port),
        of.ofp_action_output(port=cowrie_port)
        ]
        
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
        msg.idle_timeout = 60  
        self.connection.send(msg)


def launch():
    logging.getLogger("packet").setLevel(logging.CRITICAL)
    core.openflow.addListenerByName("ConnectionUp", lambda event: Security_Controller(event.connection))
