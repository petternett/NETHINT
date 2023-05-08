from scapy.all import Dot11, RadioTap, IP, IPv6
from common import ssid_mac_list, get_output, isset_gui
from gui import plot_data


""" Dot11 packets are either:
    - 0: Management
    - 1: Control
    - 2: Data
    - 3: Extension
    The meaning of addresses vary depending on which type the packet is:
        pkt[Dot11].address_meaning(1-4)
        Src: TA=SA / SA / TA
        Dst: RA=DA / RA / DA
"""

""" Relevant RadioTap 802.11 packet types:
    - QoS
    - Data
    - Acknowledgement
    - ...probably more
"""


IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_MCS  = (1 << 19)
IEEE80211_RADIOTAP_VHT  = (1 << 23)
class RadioTapPacket:
    def __init__(self, pkt) -> None:

        # --- Parse --- #
        self.raw_pkt = pkt
        self.cap_time = float(pkt.time) # in µs since epoch

        # Parse header
        self.dst_addr = pkt.addr2
        self.src_addr = pkt.addr1
        if self.dst_addr == "ff:ff:ff:ff:ff:ff": return
        if pkt.type != 2: return  # type 2: 802.11 + radiotap header

        rt = pkt[RadioTap]
        self.rate = rt.Rate
        self.rssi = rt.dBm_AntSignal
        self.noise = rt.dBm_AntNoise
        
        if get_output(): print(f"RSSI: {self.rssi}, Data rate: {self.rate}")
