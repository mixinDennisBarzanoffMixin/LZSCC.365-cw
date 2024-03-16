from ryu.lib.packet.ethernet import ethernet

class HandleEthernet:
    def __init__(self, logger):
        self.logger = logger

    def handle(self, packet):
        eth_pkt = packet.get_protocol(ethernet)
        if eth_pkt:
            self.logger.info(f"Ethernet: src={eth_pkt.src}, dst={eth_pkt.dst}, ethertype={eth_pkt.ethertype}")
