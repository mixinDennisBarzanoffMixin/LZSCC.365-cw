# -*- coding: utf-8 -*-

"""
Ryu Template Controller for Static Router coursework

You are not required to use this template, so changes to this code can be made
or you may simply use this as a reference.

Make sure to read though the template to see the `Table` classes that can be
used for static data management. 

Note: Requires Python3.8 or higher (uses the ':=' operator)
"""

from typing import Optional, Tuple, Union

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import (
    HANDSHAKE_DISPATCHER,
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
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



from solution.ethernet import HandleEthernet

import json
import sys
import ipaddress


class Router(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # A set of protocols that do not need to be forwarded in the SCC365 work.
    # This is not for any particular technical reason other than the fact they
    # can make your controller harder to debug.
    ILLEGAL_PROTOCOLS = [ipv6, lldp]

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
        dpid = dpid_to_str(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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
        if eth_pkt:
            self.logger.info(f"Ethernet: src={eth_pkt.src}, dst={eth_pkt.dst}, ethertype={eth_pkt.ethertype}")
            # if eth_pkt.dst == 'ff:ff:ff:ff:ff:ff':
            #     # Handle broadcast packet
            #     self.forward_broadcast(datapath, in_port, ev.msg.data)
            #     return

            # # dpid identifies the switch/router
            # output_port = self.determine_output_port(dpid, eth_pkt.dst)
            # if output_port is None:
            #     self.logger.error("🚨\tno output port found")
            #     return
            # self.logger.info(f"Output Port: {output_port}")
            # actions = [parser.OFPActionOutput(output_port)]
            # out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            #                           in_port=in_port, actions=actions, data=ev.msg.data)
            # datapath.send_msg(out)

        if ip_pkt:
            self.logger.info(f"IPv4: src={ip_pkt.src}, dst={ip_pkt.dst}, proto={ip_pkt.proto}")
        if arp_pkt:
            self.logger.info(f"ARP: src_ip={arp_pkt.src_ip}, dst_ip={arp_pkt.dst_ip}, src_mac={arp_pkt.src_mac}, dst_mac={arp_pkt.dst_mac}")
            self.handle_arp(datapath, in_port, eth_pkt, arp_pkt)

        if tcp_pkt:
            self.logger.info(f"TCP: src_port={tcp_pkt.src_port}, dst_port={tcp_pkt.dst_port}, seq={tcp_pkt.seq}, ack={tcp_pkt.ack}")
        if udp_pkt:
            self.logger.info(f"UDP: src_port={udp_pkt.src_port}, dst_port={udp_pkt.dst_port}")
        if icmp_pkt:
            self.logger.info(f"ICMP: type={icmp_pkt.type}, code={icmp_pkt.code}")
        self.logger.info("----- Packet Information End -----")

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
        self.logger.info(f"Sent ARP Reply: {pkt_arp.dst_ip} is at {src_mac}, which is actually {src_ip}, but we proxy direclty and lie it's our interface that's the host")


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
