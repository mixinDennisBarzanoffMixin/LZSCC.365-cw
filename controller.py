# -*- coding: utf-8 -*-

"""
Ryu Template Controller for Static Router coursework

You are not required to use this template, so changes to this code can be made
or you may simply use this as a reference.

Make sure to read though the template to see the `Table` classes that can be
used for static data management. 

Note: Requires Python3.8 or higher (uses the ':=' operator)
"""

from abc import abstractmethod
from typing import Dict, List
from typing import Optional, Tuple, Union
from netaddr import IPAddress, IPNetwork

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import (
    HANDSHAKE_DISPATCHER,
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto as inet
from ryu.lib.packet import ether_types
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp, ARP_REQUEST, ARP_REPLY
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.ipv6 import ipv6
from ryu.lib.packet.lldp import lldp
from ryu.lib.packet.icmp import icmp
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet.udp import udp
from ryu.lib.dpid import dpid_to_str
from ryu.controller.ofp_event import EventOFPPacketIn
from ryu.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP
from ryu.lib.packet.in_proto import IPPROTO_ICMP
from ryu.lib.packet.icmp import ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, ICMP_PORT_UNREACH_CODE, ICMP_TTL_EXPIRED_CODE, ICMP_HOST_UNREACH_CODE
from ryu.lib.packet.icmp import echo, dest_unreach, TimeExceeded



from solution.ethernet import HandleEthernet

import json
import sys
import ipaddress

class ICMPError(Exception):
    """
    Exception class for ICMP related errors.
    """
    def __init__(self, message="ICMP Error occurred"):
        self.message = message
        super().__init__(self.message)


class UnknownICMPError(ICMPError):
    """
    Extended ICMP Error for specific ICMP related issues, including unknown subnets.
    """
    def __init__(self, message="Extended ICMP Error occurred"):
        super().__init__(message)
   

class HostUnreachable(ICMPError):
    """
    Exception class for signaling ICMP Host Unreachable errors.
    """
    def __init__(self, message="ICMP Host Unreachable Error occurred"):
        super().__init__(message)

class HostUnknown(ICMPError):
    """
    Exception class for signaling ICMP Host Unknown errors.
    """
    def __init__(self, message="ICMP Host Unknown Error occurred"):
        super().__init__(message)


class Router(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # A set of protocols that do not need to be forwarded in the SCC365 work.
    # This is not for any particular technical reason other than the fact they
    # can make your controller harder to debug.
    ILLEGAL_PROTOCOLS = [ipv6, lldp]

    # used for icmp host unreachable tracking link up and down status
    # use mininet>link h2 r1 up/down to simulate host being disconnected from the network
    # 
    # Example of host reachability map structure:
    # {
    #     "0000000000000002": {
    #         "00:aa:aa:aa:aa:aa": True,
    #         "00:aa:aa:aa:aa:bb": False
    #     },
    #     "0000000000000003": {
    #         "00:cc:cc:cc:cc:aa": True,
    #         "00:dd:dd:dd:dd:bb": True
    #     }
    # }
    host_reachability_map: Dict[str, Dict[str, bool]] = {}

    def __init__(self, *args, **kwargs):
        """
        Init | Constructor

        Loads in/creates the static tables.
        """
        super(Router, self).__init__(*args, **kwargs)
        try:
            self.arp_table = StaticARPTable()
            self.routing_table = StaticRoutingTable()
            self.interface_table = StaticInterfaceTable()
            self.firewall_rules = FirewallRules()
            # Initialize host reachability to all true for every ARP entry
            for dpid, arp_entries in self.arp_table.get_table().items():
                self.host_reachability_map[dpid] = {entry['hw']: True for entry in arp_entries}
            self.logger.info(f"Host reachability map: {self.host_reachability_map}")

            # self.handle_ethernet = HandleEthernet(self.logger)
        except Exception as e:
            self.logger.error("🆘\t{}".format(e))
            sys.exit(1)
        if not (self.arp_table.loaded() and self.routing_table.loaded() and self.interface_table.loaded() and self.firewall_rules.loaded()):
            self.logger.error("🆘\tjson table loading was not successful")
            sys.exit(1)

    # EVENT HANDLER FUNCTIONS
    # -----------------------
    # The functions below use python function decorators so that they can be
    # automatically executed on a given OpenFlow event. They also receive the
    # information of the event as the 'ev' parameter.

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def error_msg_handler(self, ev):
        """
        OpenFlow Error Handler
        If an OpenFlow action taken by the controller results in an error at the
        switch, it will trigger an error event. This error event is caught by
        this function. Thi can drastically aide debugging.
        Event Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPErrorMsg
        """
        error = ev.msg.datapath.ofproto.ofp_error_to_jsondict(ev.msg.type, ev.msg.code)
        self.logger.error("🆘\topenflow error received:\n\t\ttype={}\n\t\tcode={}".format(error.get("type"), error.get("code")))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        """
        Handshake: Features Request Response Handler
        Installs a low priority (0) flow table modification that pushes packets
        to the controller. This acts as a rule for flow-table misses.
        As the `HELLO` message is handled by the `RyuApp` automatically, this is
        the first function in this file that will see each datapath in the
        handshake process.
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
        """
        datapath = ev.msg.datapath
        match = datapath.ofproto_parser.OFPMatch()
        dpid = dpid_to_str(datapath.id)
        self.__request_port_info(datapath)
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.__add_flow(datapath, 0, match, actions)
        self.logger.info("🤝\thandshake taken place with datapath: {}".format(dpid_to_str(datapath.id)))

    @set_ev_cls(ofp_event.EventOFPPortStatus, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            self.logger.info("Port added: %s", msg.desc.port_no)
        elif msg.reason == ofp.OFPPR_DELETE:
            self.logger.info("Port deleted: %s", msg.desc.port_no)
            # A port was deleted, indicating a host may have been disconnected
            # Update your host reachability state here
        elif msg.reason == ofp.OFPPR_MODIFY:
            self.logger.info("Port modified: %s", msg.desc.port_no)
            # update reachability status for what was connected to the port
            # A port was modified, this could indicate a link status change
            # Check msg.desc.state and update your host reachability state accordingly
            for routing_entry in self.routing_table.get_table().get(dpid_to_str(dp.id), []):
                # self.logger.info("Checking routing entry: %s", routing_entry)
                if routing_entry['out_port'] == msg.desc.port_no:
                    # self.logger.info("Matching port found in routing entry: %s", routing_entry)
                    if '/32' in routing_entry['destination']:
                        ip_address = str(IPNetwork(routing_entry['destination']).ip)
                        # self.logger.info("IP address extracted from routing entry: %s", ip_address)
                        for arp_entry in self.arp_table.get_table_for_dpid(dpid_to_str(dp.id)):
                            # self.logger.info("Checking ARP entry: %s", arp_entry)
                            if arp_entry['ip'] == ip_address:
                                mac_address = arp_entry['hw']
                                # self.logger.info("Matching ARP entry found: %s", arp_entry)
                                # this is kind of weird because the link being down can be either our fault or the other host's fault
                                # but we assume the other host is at fault because our routers are of countain perfect
                                self.host_reachability_map[dpid_to_str(dp.id)][mac_address] = msg.desc.state & ofp.OFPPS_LIVE
                                self.logger.info("Reachability updated for MAC: %s, State: %s", mac_address, msg.desc.state == ofp.OFPPS_LIVE)
                                break


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: ofp_event.EventOFPPacketIn) -> None:
        """
        Packet In Event Handler

        The bulk of your packet processing logic will reside in this function &
        all functions called from this function. There is currently NO logic
        here, so it wont do much until you edit it!

        Event Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn
        Ryu Packet Documentation:
        https://ryu.readthedocs.io/en/latest/library_packet.html#packet-library
        Ryu Packet API Documentation:
        https://ryu.readthedocs.io/en/latest/library_packet_ref.html#packet-library-api-reference
        Protocol Specific API References:
        https://ryu.readthedocs.io/en/latest/library_packet_ref.html#protocol-header-classes
        Packet Out Message Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPacketOut
        """
        datapath = ev.msg.datapath
        pkt = packet.Packet(ev.msg.data)
        in_port = ev.msg.match["in_port"]

        if self.__illegal_packet(pkt):
            return

        self.logger.info("❗️\tevent 'packet in' from datapath: {}".format(dpid_to_str(datapath.id)))

        eth_pkt: ethernet = pkt.get_protocol(ethernet)
        ip_pkt: ipv4 = pkt.get_protocol(ipv4)
        arp_pkt: arp = pkt.get_protocol(arp)
        tcp_pkt: tcp = pkt.get_protocol(tcp)
        udp_pkt: udp = pkt.get_protocol(udp)
        icmp_pkt: icmp = pkt.get_protocol(icmp)
        self.logger.info("----- Packet Information Start -----")
        if tcp_pkt:
            if tcp_pkt.dst_port == 80 or tcp_pkt.dst_port == 443:
                self.logger.info(f"HTTP/HTTPS 🌍 {ip_pkt.src}->{ip_pkt.dst}:{tcp_pkt.dst_port}")
            else:
                self.logger.info(f"TCP 🌐 {ip_pkt.src}->{ip_pkt.dst}:{tcp_pkt.dst_port}")
        elif udp_pkt:
            self.logger.info(f"UDP 🌐 {ip_pkt.src}->{ip_pkt.dst}:{udp_pkt.dst_port}")
        elif icmp_pkt:
            self.logger.info(f"ICMP 📡 type={icmp_pkt.type}, code={icmp_pkt.code}")
        elif arp_pkt:
            self.logger.info(f"ARP 🌍 {arp_pkt.src_ip}->{arp_pkt.dst_ip}")
        elif ip_pkt:
            self.logger.info(f"IP 🌐 {ip_pkt.src}->{ip_pkt.dst}")
        

        if not self.packet_allowed_by_firewall(datapath, pkt):
            return
        # if eth_pkt:
            # self.logger.info(f"Ethernet: src={eth_pkt.src}, dst={eth_pkt.dst}, ethertype={eth_pkt.ethertype}")
        if arp_pkt:
            # self.logger.info(f"ARP: src_ip={arp_pkt.src_ip}, dst_ip={arp_pkt.dst_ip}, src_mac={arp_pkt.src_mac}, dst_mac={arp_pkt.dst_mac}")
            self.handle_arp(datapath, in_port, eth_pkt, arp_pkt)
            return
       # we check if ECHO and is for one of our ips, we respond
        if icmp_pkt:
            # self.logger.info(f"ICMP: type={icmp_pkt.type}, code={icmp_pkt.code}")
            if icmp_pkt.type == ICMP_ECHO_REQUEST:
                for interface in self.interface_table.get_table_for_dpid(dpid_to_str(datapath.id)):
                     if interface['ip'] == ip_pkt.dst:
                        self.send_icmp_reply(datapath, in_port, pkt, ev)
                        return
        if ip_pkt:
            # self.logger.info(f"IPv4: src={ip_pkt.src}, dst={ip_pkt.dst}, proto={ip_pkt.proto}")
            try:
                self.forward_packet(datapath, in_port, pkt, ev)
            except UnknownICMPError as e:
                self.logger.error(f"Failed to forward packet: {e}")
                # 6 = unknown network
                self.send_icmp_unreachable_error(datapath, in_port, pkt, ev, ICMP_DEST_UNREACH, 6)
            # Note that there is no way for me to differentiate network unknown and network unreachable because I don't know the status of the routing entries
            except HostUnknown as e:
                self.logger.error(f"Failed to forward packet: {e}")
                # 7 = host unknown
                self.send_icmp_unreachable_error(datapath, in_port, pkt, ev, ICMP_DEST_UNREACH,  7)
            # like an is_active field where the network exists, but is simply not reachable at the moment. We don't have this information here.
            except HostUnreachable as e:
                self.logger.error(f"Failed to forward packet: {e}")
                self.send_icmp_unreachable_error(datapath, in_port, pkt, ev, ICMP_DEST_UNREACH,  ICMP_HOST_UNREACH_CODE)
            return

        # if tcp_pkt:
            # self.logger.info(f"TCP: src_port={tcp_pkt.src_port}, dst_port={tcp_pkt.dst_port}, seq={tcp_pkt.seq}, ack={tcp_pkt.ack}")
        # if udp_pkt:
            # self.logger.info(f"UDP: src_port={udp_pkt.src_port}, dst_port={udp_pkt.dst_port}")
        self.logger.info("----- Packet Information End -----")
        return
    
    def packet_allowed_by_firewall(self, dp, pkt: packet.Packet) -> None:
        """
        Check if the packet is allowed by the firewall
        """
        rules_table = self.firewall_rules.get_table_for_dpid(dpid_to_str(dp.id))
        sort_by_priority = sorted(rules_table, key=lambda rule: rule['priority'], reverse=True)
        for rule in sort_by_priority:
            match_found = True
            for key, value in rule['match'].items():
                # self.logger.info(f"Checking match for key: {key} with value: {value}")
                if key == "ip_proto":
                    ip_proto = pkt.get_protocol(ipv4).proto if pkt.get_protocols(ipv4) else None
                    # self.logger.info(f"ip_proto: {ip_proto}, expected: {int(value, 16)}")
                    if ip_proto != int(value, 16):
                        match_found = False
                        # self.logger.info("ip_proto match failed")
                        break
                elif key == "ip_dst":
                    ip_dst = pkt.get_protocol(ipv4).dst if pkt.get_protocols(ipv4) else None
                    # self.logger.info(f"ip_dst: {ip_dst}, expected: {value}")
                    if ip_dst != value:
                        match_found = False
                        # self.logger.info("ip_dst match failed")
                        break
                elif key == "tcp_dst":
                    tcp_dst = pkt.get_protocol(tcp).dst_port if pkt.get_protocols(tcp) else None
                    # self.logger.info(f"tcp_dst: {tcp_dst}, expected: {int(value)}")
                    if tcp_dst != int(value):
                        match_found = False
                        # self.logger.info("tcp_dst match failed")
                        break
                elif key == "udp_dst":
                    udp_dst = pkt.get_protocol(udp).dst_port if pkt.get_protocols(udp) else None
                    # self.logger.info(f"udp_dst: {udp_dst}, expected: {int(value)}")
                    if udp_dst != int(value):
                        match_found = False
                        # self.logger.info("udp_dst match failed")
                        break
                elif key == "eth_type":
                    eth_type = pkt.get_protocol(ethernet).ethertype if pkt.get_protocols(ethernet) else None
                    # self.logger.info(f"eth_type: {eth_type}, expected: {int(value, 16)}")
                    if eth_type != int(value, 16):
                        match_found = False
                        # self.logger.info("eth_type match failed")
                        break
                else:
                    match_found = False
                    # self.logger.info("No matching key found")
                    break
            if match_found:
                if rule['allow']:
                    self.logger.info(f"🔑✅ Packet matches rule {rule['description']} and is allowed")
                    return True
                else:
                    self.logger.info(f"🔒🚫 Packet matches rule {rule['description']} and is denied")
                    return False
            else:
                self.logger.info(f"🔍 Rule {rule['description']} - no match, checking next rule")
        self.logger.info("🚫 No matching rule found, packet dropped")
        return False

    def send_icmp_unreachable_error(self, datapath, in_port, pkt, ev, type, code):
        """
        Generate and send an ICMP error message for packets destined to unknown subnets.
        """
        pkt_ipv4 = pkt.get_protocol(ipv4)
        # first figure out which subnet the src ip is in, then we find which interface is in that subnet
        for subnet in self.routing_table.get_table_for_dpid(dpid_to_str(datapath.id)):
            if IPAddress(pkt_ipv4.src) in IPNetwork(subnet['destination']):
                out_port = subnet['out_port']
                break
        
        if out_port is None:
            self.logger.error("🚨\tNo output port found for interface during ICMP error message handling")
            return
        for eth_entry in self.interface_table.get_table_for_dpid(dpid_to_str(datapath.id)):
            if eth_entry['port'] == out_port:
                src_ip = eth_entry['ip']
                break
        if src_ip is None:
            self.logger.error("🚨\tNo source IP found for interface during ICMP error message handling")
            return
        # we need to send an ICMP error message to the src ip and mac address
        self.logger.info("🚨 Generating ICMP Error Message {}:{}".format(type, code))
        eth_header_length = 14  # Ethernet header length
        original_ip_icmp_data = pkt.data[eth_header_length:eth_header_length+28]  # Skip Ethernet header, then IP header (20 bytes) + first 8 bytes of payload

        original_pkt_data = dest_unreach(data=original_ip_icmp_data)
        
        self.send_icmp_reply_general(datapath, in_port, pkt, ev, type, code, src_ip, original_pkt_data)


    def send_icmp_reply(self, datapath, in_port, pkt, ev):
        """
        Generate and send an ICMP reply for an ICMP request.
        """
        pkt_ipv4 = pkt.get_protocol(ipv4)
        # precondition is they sent to us, so dst is our address
        src_ip = pkt_ipv4.dst
        self.send_icmp_reply_general(datapath, in_port, pkt, ev, ICMP_ECHO_REPLY, 0, src_ip, pkt.get_protocol(icmp).data)

    def send_icmp_reply_general(self, datapath, in_port, pkt, ev, icmp_type, icmp_code, src_ip, icmp_data):
        """
        Generate and send an ICMP reply for an ICMP request.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt_ethernet: ethernet = pkt.get_protocol(ethernet)
        pkt_ipv4: ipv4 = pkt.get_protocol(ipv4)

        if not pkt_ethernet or not pkt_ipv4:
            self.logger.error("🚨\tMissing protocol layer for ICMP reply")
            return

        # to send an ICMP reply, we need to reply to the src ip and mac address
        src_mac = pkt_ethernet.dst
        dst_mac = pkt_ethernet.src
        dst_ip = pkt_ipv4.src
        # pkt_ipv4 might not always be right, we need to get the ip address for the interface
        # by default to who sent it
        if src_ip is None:
            src_ip = pkt_ipv4.dst

        self.logger.info(f"Sending ICMP reply to {dst_ip}")

        # create new packet out message
        actions = [parser.OFPActionOutput(in_port)]
        out_pkt_ethernet = ethernet(dst=dst_mac, src=src_mac, ethertype=ETH_TYPE_IP)
        out_pkt_ip = ipv4(dst=dst_ip, src=src_ip, proto=IPPROTO_ICMP)
        out_pkt_icmp = icmp(type_=icmp_type, code=icmp_code, csum=0, data=icmp_data)
        out_pkt = packet.Packet()
        out_pkt.add_protocol(out_pkt_ethernet)
        out_pkt.add_protocol(out_pkt_ip)
        out_pkt.add_protocol(out_pkt_icmp)
        out_pkt.serialize()

        self.logger.info(f"✅ Sending ICMP reply from {src_ip} to {dst_ip}, MAC from {src_mac} to {dst_mac}")
        # using OFPP_ANY or OFPP_CONTROLLER as the output port in order to bypass OpenFlow switch rules, just send it directly
        # otherwise the switch does not want to send it
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=out_pkt.data);
        datapath.send_msg(out)
        return

    # the full packet is passed to this function, so we can get the other layers, not just ethernet and ip
    def forward_packet(self, datapath, in_port, pkt: packet.Packet, ev: ofp_event.EventOFPPacketIn):
        """
        Forward the packet to the next hop
        """
        pkt_ipv4: ipv4 = pkt.get_protocol(ipv4)
        if not pkt_ipv4:
            self.logger.error("🚨\tno ipv4 packet found")
            return
        pkt_ethernet: ethernet = pkt.get_protocol(ethernet)
        if not pkt_ethernet:
            self.logger.error("🚨\tno ethernet packet found")
            return
        # find the entry from the routing table
        routing_table = self.routing_table.get_table_for_dpid(dpid_to_str(datapath.id))
        dst_ip = pkt_ipv4.dst
        output_port = None
        for routing_entry in routing_table:
            if IPAddress(dst_ip) in IPNetwork(routing_entry['destination']):
                output_port = routing_entry['out_port']
                # self.logger.info(f"✅ Output Port: {output_port}")
                break;

        if not output_port:
            self.logger.error("🚨\tno output port found")
            raise UnknownICMPError(f"Subnet unknown for ip: {IPAddress(dst_ip)}")

        actions = [datapath.ofproto_parser.OFPActionOutput(output_port)]

        # mac address changes, otherwise next host won't care about it
        # for src_mac, we need to find the mac address on the same interfacea as this IPNetwork
        src_mac = None
        dst_mac = None
        for interface_entry in self.interface_table.get_table_for_dpid(dpid_to_str(datapath.id)):
            if interface_entry['port'] == output_port:
                src_mac = interface_entry['hw']
                break
        # now, dst_ip is not always accurate here, what if it's another router, we need to use next hop ip
        if routing_entry['hop']:
            dst_ip = routing_entry['hop']
        for arp_entry in self.arp_table.get_table_for_dpid(dpid_to_str(datapath.id)):
            if arp_entry['ip'] == dst_ip:
                dst_mac = arp_entry['hw']
                break
        if not dst_mac:
            self.logger.error("🚨\tno dst mac address found for ip: {}".format(IPAddress(dst_ip)))
            raise HostUnreachable(f"No ARP entry for ip: {IPAddress(dst_ip)}")
        if not src_mac:
            self.logger.error("🚨\tno src mac address found for source interface: {}".format(routing_entry['destination']))
            return
        
        reachability_map = self.host_reachability_map[dpid_to_str(datapath.id)]
        if (reachability_map[dst_mac] == False):
            self.logger.error("🚨\tHost is unreachable")
            raise HostUnreachable(f"Host is unreachable")
    
        e = ethernet(dst=dst_mac, src=src_mac, ethertype=pkt_ethernet.ethertype)
        p = packet.Packet()
        p.add_protocol(e)
        # there was a problem where the packets TX transmitted were bigger than RX received
        # I was forgetting to add the other layers, it was confusing as h2 was receiving h1's pings, but not replying
        # and they were like 50% smaller packets, so I figured it was a good idea to add the other layers lol
        protocols = pkt.protocols
        # self.logger.info(protocols)
        for protocol in protocols[1:]:
            p.add_protocol(protocol)
        p.serialize()
        self.logger.info(f"✅ Output Port: {output_port}, {pkt_ipv4.src}:{pkt_ipv4.dst} {src_mac}:{dst_mac}")
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                    in_port=in_port, actions=actions, data=p.data)
        datapath.send_msg(out)
        return

    def handle_arp(self, datapath, in_port, pkt_ethernet: ethernet, pkt_arp: arp):
        """
        Handle ARP packets
        We need to find the entry in the interfaces.json that matches the in_port.
        """
        # Check if it's an ARP request
        if pkt_arp.opcode != ARP_REQUEST:
            return  # Only handle ARP requests

        dpid = dpid_to_str(datapath.id)
        interface = self.interface_table.get_interface(dpid, in_port)
        if interface:
            self.logger.info(f"Interface ARP Reply: {interface['hw']}")
        else:
            self.logger.error("🚨\tno interface found for in_port: {}".format(in_port))
        
        hw = interface["hw"]
        self.send_arp_reply(datapath, in_port, pkt_ethernet, pkt_arp, interface)

    def send_arp_reply(self, datapath, in_port, pkt_ethernet: ethernet, pkt_arp: arp, interface):
        """
        Send an ARP reply in response to an ARP request for one of the router's interfaces.
        We are implementing ARP Proxying. H1 pings H2, they are in different subnets. 
        The router has an ARP table and doesn't have to flood the network, so it pretends to be H2
        and gives its own interface MAC address, pretending it's H2 (pkt_arp.dst_ip as the src_ip). 
        """
        src_mac = interface['hw']  # MAC address of the router's interface
        src_ip = interface['ip']  # IP address of the router's interface

        # Construct ARP reply packet
        e = ethernet(dst=pkt_ethernet.src,
                            src=src_mac,
                            ethertype=ETH_TYPE_ARP)
        a = arp(opcode=ARP_REPLY,
                    src_mac=src_mac,
                    src_ip=pkt_arp.dst_ip,
                    dst_mac=pkt_arp.src_mac,
                    dst_ip=pkt_arp.src_ip)

        # Create the packet
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        # Send the ARP reply packet
        actions = [datapath.ofproto_parser.OFPActionOutput(port=in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                actions=actions,
                                                data=p.data)
        datapath.send_msg(out)
        self.logger.info(f"✅ Sent ARP Reply: {pkt_arp.dst_ip} is at {src_mac}, which is actually {src_ip}, but we proxy directly and pretend it's our interface that's the host")


    # def forward_broadcast(self, datapath, in_port, data):
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser

    #     # Get all ports for this datapath (switch)
    #     ports = self.get_datapath_ports(datapath.id)

    #     actions = [parser.OFPActionOutput(port) for port in ports if port != in_port]

    #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
    #                             in_port=in_port, actions=actions, data=data)
    #     datapath.send_msg(out)

    # def get_datapath_ports(self, dpid):
    #     # Placeholder for getting all ports of a datapath (switch)
    #     # You might maintain a structure that tracks this information
    #     # based on port status messages from the switch
    #     return [1, 2, 3]  # Example: return a list of port numbers

    # def determine_output_port(self, dpid, dst_mac):
    #     current_switch_table = self.interface_table.get_table_for_dpid(dpid)
    #     # this is a list of the dic in the interfaces.json
    #     # we have to filter out by hw (MAC) and then get the port

    #     self.logger.info("dst_mac: {}".format(dst_mac))
    #     for entry in current_switch_table:
    #         self.logger.info(f"entry: {entry}")
    #         if entry["hw"] == dst_mac:
    #             return entry["port"]
    #     return None

    # SUPPORT FUNCTIONS
    # -----------------
    # Functions that may help with NAT router implementation
    # The functions below are used in the default NAT router. These
    # functions don't directly handle openflow events, but can be
    # called from functions that do

    def __add_flow(self, datapath, priority, match, actions, idle=60, hard=0):
        """
        Install Flow Table Modification
        Takes a set of OpenFlow Actions and a OpenFlow Packet Match and creates
        the corresponding Flow-Mod. This is then installed to a given datapath
        at a given priority.
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPFlowMod
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard,
        )
        self.logger.info(
            "✍️\tflow-Mod written to datapath: {}".format(dpid_to_str(datapath.id))
        )
        datapath.send_msg(mod)

    def __illegal_packet(self, pkt, log=False):
        """
        Illegal Packet Check
        Checks to see if a packet is allowed to be forwarded. You should use
        these pre-populated values in your coursework to avoid issues.
        """
        for proto in self.ILLEGAL_PROTOCOLS:
            if pkt.get_protocol(proto):
                if log:
                    self.logger.debug("🚨\tpacket with illegal protocol seen: {}".format(proto.__name__))
                return True
        return False

    def __request_port_info(self, datapath):
        """
        Request Datapath Port Descriptions
        Create a Port Desc Stats Request and send it to the given datapath. The
        response for this will come in asynchronously in the function that
        handles the event `EventOFPPortDescStatsReply`.
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPortDescStatsRequest
        """
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
        self.logger.debug(
            "📤\trequesting datapath port information: {}".format(
                dpid_to_str(datapath.id)
            )
        )

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def __port_info_handler(self, ev):
        """
        Handle a OFPPortDescStatsReply event
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPortDescStatsReply
        """
        dpid = dpid_to_str(ev.msg.datapath.id)
        for p in ev.msg.body:
            self.logger.info(p.port_no)
            self.logger.info(p.hw_addr)
        self.logger.debug("❗️\tevent 'PortDescStatsReply' received!")
    

"""
Table

Represents a generic static data table, used by ARP, Routing, and Interface
tables.

As use of this template file is entirely optional, you are of course free to
modify these classes however you desire.
"""


class Table():

    def __init__(self, path: str = ""):
        self._table, from_file = self.__load_data(path)
        self._loaded = from_file
        if not from_file:
            print("using an empty {} table: read from file failed".format(self.__class__.__name__))

    def loaded(self) -> bool:
        """
        Loaded

        Returns True if the table was loaded from file, False otherwise.
        """
        return self._loaded

    def get_table(self) -> dict:
        """
        Get Table

        Returns the entire loaded table (as a dictionary)
        """
        return self._table

    def get_table_for_dpid(self, dpid: str) -> Optional[dict]:
        """
        Get Table for DPID

        Returns the entries in a table associated with a given datapath. Returns
        'None' if the DPID does not exist in the table.
        """
        if dpid in self._table:
            return self._table[dpid]
        return None

    def __load_data(self, path: str) -> Tuple[dict,  bool]:
        try:
            with open(path, 'r') as f:
                return json.load(f), True
        except:
            return {}, False
        
    def dump_table(self):
        """
        Dump Table to Stdout (pretty)

        Prints a dictionary in JSON format to the std out. This is useful for
        debugging.   
        """
        print(
            json.dumps(
                self._table,
                sort_keys=True,
                indent=2,
                separators=(",", ": ")
            )
        )


"""
Static ARP Table (extends Table)

Should contain a table with the static ARP data along with helper functions to
access the data.
"""


class StaticARPTable(Table):

    ARP_PATH = './arp.json'

    def __init__(self, path: str = ARP_PATH):
        super().__init__(path=path)

    def get_ip(self, dpid: str, mac: str) -> Optional[str]:
        """
        Get IP

        Returns the IP address associated with the given MAC address (or 'None')
        """
        for x in self._table[dpid]:
            if x['hw'] == mac:
                return x['ip']
        return None

    def get_hw(self, dpid: str, ip: str) -> Optional[str]:
        """
        Get MAC

        Returns the MAC address associated with the given IP address (or 'None')
        """
        for x in self._table[dpid]:
            if x['ip'] == ip:
                return x['hw']
        return None


"""
Static Routing Table (extends Table)

Should contain a table with the static routing data along with helper functions
to access the data.
"""


class StaticRoutingTable(Table):

    ROUTING_PATH = './routing.json'

    def __init__(self, path=ROUTING_PATH):
        super().__init__(path=path)

    def get_next_hop(self, dpid: str, ip: str) -> Optional[str]:
        """
        Get Next Hop

        Returns the IP address of the next hop towards a given IP address, if
        direct or IP address is not in the table, None is returned.
        """
        for x in self._table[dpid]:
            if any([x['destination'] == ip,
                    ipaddress.ip_address(ip) in ipaddress.ip_network(x['destination'])]):
                return x['hop']
        return None

    def get_route(self, dpid: str, ip: str) -> Tuple[Optional[str], Optional[int], Optional[bool]]:
        """
        Get Route

        Returns the IP address of the next hop towards a given IP address, if
        direct or IP address is not in the table, None is returned.
        """
        for x in self._table[dpid]:
            if any([x['destination'] == ip,
                    ipaddress.ip_address(ip) in ipaddress.ip_network(x['destination'])]):
                return x['hop'], x['out_port'], x['nat']
        return None, None, None


"""
Static Interfaces Table (extends Table)

Should contain a table with the static Interfaces data along with helper
functions to access the data.
"""


class StaticInterfaceTable(Table):

    INTERFACES_PATH = './interfaces.json'

    def __init__(self, path=INTERFACES_PATH):
        super().__init__(path=path)

    def get_interface(self,  dpid: str, port: int) -> Optional[dict]:
        """
        Get Interface

        Retruns an interface entry for a given datapath and port. If no entry
        exists, for the given datapath and port, None is returned.
        """
        for x in self._table[dpid]:
            if x['port'] == port:
                return x
        return None
    
    def get_interface_by_hw(self,  dpid: str, hw: str) -> Optional[dict]:
        """
        Get Interface By HW

        Retruns an interface entry for a given datapath and mac address. If no
        entry exists, for the given datapath and mac address, None is returned.
        """
        for x in self._table[dpid]:
            if x['hw'] == hw:
                return x
        return None
    

"""
Firewall Rules (extends Table)

Represents a set of firewall rules as described in the coursework specification.
Although this is not a table, it shares much of the logic with the tables above,
so it is implemented as a table.
"""

class FirewallRules(Table):

    RULES_PATH = './rules.json'

    def __init__(self, path=RULES_PATH):
        super().__init__(path=path)

    def get_rules(self,  dpid: str) -> Optional[list]:
        """
        Get Rules

        Returns the rules for a given datapath ID (full 16 char string). If the
        rules set does not have ay rules for the given datapath, None is
        returned.
        """
        if dpid in self._table:
            return self._table[dpid]
        return None
