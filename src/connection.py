from common import printn


connections = {}  # TODO: move to persistent storage
global_cid = global_fid = 0

def find_connection(addr_a, port_a, addr_b, port_b):
    global connections, global_cid

    key_a = f"{addr_a}:{port_a}>{addr_b}:{port_b}"
    key_b = f"{addr_b}:{port_b}>{addr_a}:{port_a}"

    # Return existing connection object
    con = connections.get(key_a)
    if con is None:
        con = connections.get(key_b)
    if con is not None:
        return con

    # Create new connection object
    con = Connection(global_cid, addr_a, port_a, addr_b, port_b)
    global_cid += 1
    connections[key_a] = con

    return con


class Connection:
    def __init__(self, cid: int, addr_a: str, port_a:
                 int, addr_b: str, port_b: int) -> None:
        global global_fid
        self.cid = cid

        self.addr_a = addr_a
        self.port_a = port_a
        self.addr_b = addr_b
        self.port_b = port_b

        self.fwd = Flow(global_fid, self.cid)
        global_fid += 1
        self.rev = Flow(global_fid, self.cid)
        global_fid += 1

        self.fwd.rev = self.rev
        self.rev.rev = self.fwd
        
        self.syn_found = False
        self.fin_found = False


class Flow:
    def __init__(self, fid: int, cid: int) -> None:
        self.fid = fid
        self.cid = cid
        self.prev_pkts = []
        self.rev = None  # Opposite flow direction of packet
        self.cap_time = 0
        self.rtt = 0
        # TCP
        self.pair_pkts = {}  # ack -> TCPPacket
        self.ts_pair   = {}  # ts  -> TCPPacket
        self.next_seq = 0
        self.last_ack = 0
        self.window = 0
        self.max_to_ack = 0
        self.tsval = 0
        self.tsecr = 0
        self.owd_base = None
        self.owd = None

        # QUIC
        self.spin_enabled = False

    def add_pkt(self, pkt):
        self.prev_pkts.append(pkt)

    # Get prev pkt, use argument to get the n-th last packet
    def get_prev_pkt(self, n=1):
        if self.num_pkts() < n:
            return None
        return self.prev_pkts[-n]

    def num_pkts(self):
        return len(self.prev_pkts)

    def print_pkts(self):
        # this sucks
        print("Packets so far:")
        for pkt in self.prev_pkts:
            printn(f"SEQ: {pkt.pkt[TCP].seq} - ACK: {pkt.pkt[TCP].ack}, ")
        print()
