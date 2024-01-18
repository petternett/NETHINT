from scapy.all import (
        TCP,
        UDP,
        ICMP,
        IP,
        IPv6,
        ARP,
        Ether,
        ETHER_BROADCAST,
        RadioTap,
        Dot11,
        Dot11Beacon
    )
from scapy.packet import *
from scapy.utils import wrpcap
from QUIC import QUIC

from collections import defaultdict
from datetime import datetime

from common import (
        printn,
        get_ssid,
        add_mac,
        is_valid_ssid,
        get_output,
        isset_gui,
        isset_log,
        isset_relative_time,
        get_time_base,
        set_time_base,
        check_mode,
        check_from_local,
        get_write_pcap,
    )
from TCPPacket import TCPPacket
from QUICPacket import QUICPacket
from RadioTapPacket import RadioTapPacket
from DataPoint import DataPoint
from logger import logger_add
from gui import plot_data

PLOT_RTT  = 0
PLOT_LOSS = 1
PLOT_OWD  = 2
UPDATE_VALUE = 3

bind_layers(UDP, QUIC, sport=443)
bind_layers(UDP, QUIC, dport=443)

total_pkts = 0
total_valid_rtts = 0

def process_packet(pkt):
    global total_pkts, total_valid_rtts
    total_pkts += 1

    if get_write_pcap():
        wrpcap(get_write_pcap(), pkt, append=True)

    if get_output(): print()
    if get_output(): printn(f"{total_pkts} ")

    ip_ver = None
    if pkt.haslayer(IP): ip_ver = IP
    if pkt.haslayer(IPv6): ip_ver = IPv6

    time = datetime.fromtimestamp(float(pkt.time)).strftime("%D %H:%M:%S.%f")
    if get_output(): printn(f"{time} ")

    # -- Check packet type -- #

    """ 802.11 Beacon packet.
        These packets give us the MAC address of the AP's with the defined SSID.
    """
    if pkt.haslayer(Dot11Beacon):
        if get_output(): print(f"802.11 Beacon frame - {pkt.addr2}, SSID: {pkt.info.decode('utf-8')}")
        if pkt.info.decode('utf-8') == get_ssid() and not is_valid_ssid(pkt.addr2):
            add_mac(pkt.addr2)

        return


    if pkt.haslayer(TCP):

        # Relative time
        cap_time = float(pkt.time) # in s since epoch with µs precision
        rel_time = cap_time
        if get_time_base() is None:
            set_time_base(cap_time)
        rel_time -= get_time_base()

        # RadioTap packet
        radio_pkt = None
        if pkt.haslayer(RadioTap):
            if not is_valid_ssid(pkt.addr1) and not is_valid_ssid(pkt.addr2):
                return

            if get_output(): print(f"RadioTap - {pkt.addr2} > {pkt.addr1}")

            radio_pkt = RadioTapPacket(pkt)

        # TCP
        if get_output():
            printn(f"TCP - {pkt[ip_ver].src}:{pkt[TCP].sport} > {pkt[ip_ver].dst}:{pkt[TCP].dport}")
            print(f" seq {pkt[TCP].seq}, ack {pkt[TCP].ack}, len {len(pkt[TCP].payload)}")

        tcp_pkt = TCPPacket(pkt, ip_ver)
        valid_rtt = tcp_pkt.rtt is not None
        if valid_rtt: total_valid_rtts += 1

        # Get MAC addresses from either wireless or Ether header
        if isset_log() or isset_gui():
            if check_mode() == "wireless":
                mac_src = pkt.addr2
                mac_dst = pkt.addr1
            else:
                mac_src = pkt[Ether].src
                mac_dst = pkt[Ether].dst

        rssi = rate = noise = None
        if radio_pkt is not None:
            rssi = radio_pkt.rssi
            rate = radio_pkt.rate
            noise = radio_pkt.noise

        # --- Log data --- #
        if isset_log():
            if get_output(): print(f"Total valid RTTs: {total_valid_rtts}")
            log_obj = {
                    "proto":      "TCP",
                    "ip_src":     pkt[ip_ver].src,
                    "ip_dst":     pkt[ip_ver].dst,
                    "port_src":   pkt[TCP].sport,
                    "port_dst":   pkt[TCP].dport,
                    "mac_src":    mac_src,
                    "mac_dst":    mac_dst,
                    "rel_time":   rel_time,
                    "cap_time":   cap_time,
                    "rtt":        tcp_pkt.rtt,
                    "rssi":       rssi,
                    "rate":       rate,
                    "noise":      noise,
                    "owd_diff":   tcp_pkt.owd_diff,
                    "owd":        tcp_pkt.flow_direction.owd,
                    "tsval":      tcp_pkt.tsval,
                    "tsval_diff": tcp_pkt.tsval_diff,
                    "tsecr":      tcp_pkt.tsecr,
                    "is_lost":    tcp_pkt.is_lost,
                    "cid":        tcp_pkt.cid,
                    "fid":        tcp_pkt.fid,
                   }
            logger_add(log_obj)

        # --- Plot data --- #
        if isset_gui():
            send_time = rel_time if isset_relative_time() else cap_time

            # Send updated bottleneck value to GUI
            plot_data((UPDATE_VALUE, f"Number of packets: {total_pkts}"))

            # Plot RTT
            if valid_rtt:
                data_point = DataPoint(mac_dst, mac_src,
                                       pkt[ip_ver].src, pkt[ip_ver].dst,
                                       pkt[TCP].sport, pkt[TCP].dport,
                                       send_time,
                                       (tcp_pkt.rtt/1000, rssi, rate, noise))

                plot_data((PLOT_RTT, data_point))

            # Plot packet loss
            if tcp_pkt.is_lost or tcp_pkt.is_retransmission:
                data_point = DataPoint(mac_dst, mac_src,
                                       pkt[ip_ver].src, pkt[ip_ver].dst,
                                       pkt[TCP].sport, pkt[TCP].dport,
                                       send_time, None)

                plot_data((PLOT_LOSS, data_point))

            # Plot OWD
            if tcp_pkt.owd_diff is not None:
                data_point = DataPoint(mac_dst, mac_src,
                                       pkt[ip_ver].src, pkt[ip_ver].dst,
                                       pkt[TCP].sport, pkt[TCP].dport,
                                       send_time, tcp_pkt.owd_diff)

                plot_data((PLOT_OWD, data_point))

        return


    if pkt.haslayer(QUIC):

        # Relative time
        cap_time = float(pkt.time)  # in µs since epoch
        rel_time = cap_time
        if get_time_base() is None:
            set_time_base(cap_time)
        rel_time -= get_time_base()

        # RadioTap packet
        radio_pkt = None
        if pkt.haslayer(RadioTap):
            if not is_valid_ssid(pkt.addr1) and not is_valid_ssid(pkt.addr2):
                return

            if get_output(): print(f"RadioTap - {pkt.addr2} > {pkt.addr1}")

            radio_pkt = RadioTapPacket(pkt)

        # QUIC packet
        if get_output():
            printn(f"QUIC - {pkt[ip_ver].src}:{pkt[UDP].sport} > {pkt[ip_ver].dst}:{pkt[UDP].dport}")
            print(f" len {len(pkt[UDP].payload)}")

        # Get MAC addresses from either wireless or Ether header
        if isset_log() or isset_gui():
            if check_mode() == "wireless":
                mac_src = pkt.addr2
                mac_dst = pkt.addr1
            else:
                mac_src = pkt[Ether].src
                mac_dst = pkt[Ether].dst

        rssi = rate = noise = None
        if radio_pkt is not None:
            rssi = radio_pkt.rssi
            rate = radio_pkt.rate
            noise = radio_pkt.noise

        quic_pkt = QUICPacket(pkt, ip_ver)
        valid_rtt = quic_pkt.rtt is not None

        # --- Log data --- #
        if isset_log() and valid_rtt:
            log_obj = {
                    "proto":    "QUIC",
                    "ip_src":   pkt[ip_ver].src,
                    "ip_dst":   pkt[ip_ver].dst,
                    "port_src": pkt[UDP].sport,
                    "port_dst": pkt[UDP].dport,
                    "mac_src":  mac_src,
                    "mac_dst":  mac_dst,
                    "rel_time": rel_time,
                    "cap_time": cap_time,
                    "rtt":      quic_pkt.rtt,
                    "rssi":     rssi,
                    "rate":     rate,
                    "noise":    noise,
                    "cid":      quic_pkt.cid,
                    "fid":      quic_pkt.fid,
                   }
            logger_add(log_obj)

        # --- Plot data --- #
        send_time = rel_time if isset_relative_time() else cap_time
        if isset_gui() and valid_rtt:
            data_point = DataPoint(mac_dst, mac_src,
                                   pkt[ip_ver].src, pkt[ip_ver].dst,
                                   pkt[UDP].sport, pkt[UDP].dport,
                                   send_time,
                                   (quic_pkt.rtt/1000, rssi, rate, noise))

            plot_data((PLOT_RTT, data_point))

        return


    if pkt.haslayer(ICMP):
        if get_output():
            printn(f"ICMP - {pkt[ip_ver].src} > {pkt[ip_ver].dst}, ")
            print(f"type {pkt[ICMP].type}, id {pkt[ICMP].id}, "
                  f"seq {pkt[ICMP].seq}, len {len(pkt[ICMP].payload)}")
        return


    if pkt.haslayer(ARP):
        if pkt[ARP].op == 1:
            if pkt[ARP].psrc == pkt[ARP].pdst:
                if get_output(): print(f"ARP - Announcement: {pkt[ARP].psrc} has {pkt[ARP].hwsrc}")
                return

            if get_output(): print(f"ARP - who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}")
            return

        if pkt[ARP].op == 2:
            if pkt[ARP].hwdst == ETHER_BROADCAST:
                if get_output(): print(f"Gratuitous ARP: {pkt[ARP].psrc} is {pkt[ARP].hwsrc}")
                return

            if get_output(): print(f"ARP reply to {pkt[ARP].pdst}: {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")
            return


        if get_output(): print("WARNING: unknown ARP-type packet")
        if get_output(): print(pkt.show())
        return


    if pkt.haslayer(Dot11):
        if get_output(): print(f"Detected 802.11 packet, type: {pkt.type}, subtype: {pkt.subtype}")
        return


    if get_output(): print("Detected unknown packet")
    # print(pkt.show())
