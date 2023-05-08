""" A DataPoint can either be a valid RTT or just a lost packet.
"""
class DataPoint:
    def __init__(self, mac_a: str, mac_b: str, ip_src: str, ip_dst: str,
                 port_a: str, port_b: str, time: float, data) -> None:
        self.mac_a: str = mac_a
        self.mac_b: str = mac_b
        self.ip_src: str = ip_src
        self.ip_dst: str = ip_dst
        self.port_a: str = port_a
        self.port_b: str = port_b
        self.time: float = time
        self.data = data
