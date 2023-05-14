from mininet.topo import Topo
from mininet.node import Node
from mininet.link import Link, TCLink
from mininet.cli import CLI
from mininet.term import makeTerm
import time
import os

# usage:
# sudo mn --custom topo.py --topo equalbw --link tc

# inside mininet:
# mininet> init_test

# Please note that tc settings will only be applied after running a function.
# netem delay RTT (not OWD!)


class FullTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # Create topology
        r1 = self.addHost('r1', ip='10.1.0.1/24', defaultRoute='via 10.1.0.2', cls=LinuxRouter)
        h1 = self.addHost('h1', ip='10.1.1.100/24', defaultRoute='via 10.1.1.1')
        h2 = self.addHost('h2', ip='10.1.2.100/24', defaultRoute='via 10.1.2.1')

        r2 = self.addHost('r2', ip='10.1.0.2/24', defaultRoute='via 10.1.0.1', cls=LinuxRouter)
        h3 = self.addHost('h3', ip='10.1.3.100/24', defaultRoute='via 10.1.3.1')
        h4 = self.addHost('h4', ip='10.1.4.100/24', defaultRoute='via 10.1.4.1')

        self.addLink(r1, r2, intfName1='r1-r2', intfName2='r2-r1', cls=TCLink,
                     params1={'ip': '10.1.0.1/24'},
                     params2={'ip': '10.1.0.2/24'})

        self.addLink(h1, r1, intfName1='h1-r1', intfName2='r1-h1', cls=TCLink,
                     params2={'ip': '10.1.1.1/24'})
        self.addLink(h2, r1, intfName1='h2-r1', intfName2='r1-h2', cls=TCLink,
                     params2={'ip': '10.1.2.1/24'})

        self.addLink(h3, r2, intfName1='h3-r2', intfName2='r2-h3', cls=TCLink,
                     params2={'ip': '10.1.3.1/24'})
        self.addLink(h4, r2, intfName1='h4-r2', intfName2='r2-h4', cls=TCLink,
                     params2={'ip': '10.1.4.1/24'})

class Sit1Topo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # Create topology
        h1 = self.addHost('h1', ip='10.1.1.100/24', defaultRoute='via 10.1.1.1')
        h2 = self.addHost('h2', ip='10.1.2.100/24', defaultRoute='via 10.1.2.1')

        r1 = self.addHost('r1', ip=None, cls=LinuxRouter)
        r2 = self.addHost('r2', ip=None, cls=LinuxRouter)
        r3 = self.addHost('r3', ip=None, cls=LinuxRouter)

        h3 = self.addHost('h3', ip='10.2.1.100/24', defaultRoute='via 10.2.1.1')
        h4 = self.addHost('h4', ip='10.2.2.100/24', defaultRoute='via 10.2.2.1')

        self.addLink(r1, r2, intfName1='r1-r2', intfName2='r2-r1', cls=TCLink,
                     params1={'ip': '10.1.0.1/24'},
                     params2={'ip': '10.1.0.2/24'})
        self.addLink(r2, r3, intfName1='r2-r3', intfName2='r3-r2', cls=TCLink,
                     params1={'ip': '10.2.0.2/24'},
                     params2={'ip': '10.2.0.1/24'})

        self.addLink(h1, r1, intfName1='h1-r1', intfName2='r1-h1', cls=TCLink,
                     params2={'ip': '10.1.1.1/24'})
        self.addLink(h2, r1, intfName1='h2-r1', intfName2='r1-h2', cls=TCLink,
                     params2={'ip': '10.1.2.1/24'})

        self.addLink(h3, r3, intfName1='h3-r3', intfName2='r3-h3', cls=TCLink,
                     params2={'ip': '10.2.1.1/24'})
        self.addLink(h4, r3, intfName1='h4-r3', intfName2='r3-h4', cls=TCLink,
                     params2={'ip': '10.2.2.1/24'})


def sit1_test(self, line):
    net = self.mn
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    r1 = net.get('r1')
    r2 = net.get('r2')
    r3 = net.get('r3')

    r1.cmd("ip route add 10.2/16 via 10.1.0.2 dev r1-r2")
    r2.cmd("ip route add 10.1/16 via 10.1.0.1 dev r2-r1")
    r2.cmd("ip route add 10.2/16 via 10.2.0.1 dev r2-r3")
    r3.cmd("ip route add 10.1/16 via 10.2.0.2 dev r3-r2")

    # Disable hardware offloading
    h1.cmd("ethtool -k h1-r1 tso off;\
            ethtool -k h1-r1 gso off;\
            ethtool -k h1-r1 lro off;\
            ethtool -k h1-r1 gro off;\
            ethtool -k h1-r1 ufo off;")
    h2.cmd("ethtool -K h2-r1 tso off;\
            ethtool -K h2-r1 gso off;\
            ethtool -K h2-r1 lro off;\
            ethtool -K h2-r1 gro off;\
            ethtool -K h2-r1 ufo off;")

    # Traffic control
    l_delay = 20 # 0
    l_bw = 10   # 50
    l_qsize = int((l_bw * 125000) * (l_delay * 0.001))
    print(l_qsize)
    r2.cmd(f"tc qdisc del dev r2-r3 root;\
            tc qdisc add dev r2-r3 root handle 2: netem delay {l_delay}ms;\
            tc qdisc add dev r2-r3 parent 2: handle 3: htb default 10;\
            tc class add dev r2-r3 parent 3: classid 10 htb rate {l_bw}Mbit;\
            tc qdisc add dev r2-r3 parent 3:10 handle 11: bfifo limit {l_qsize};")

    #r2.cmd(f"tc qdisc del dev r2-r1 root;\
    #        tc qdisc add dev r2-r1 root handle 2: netem delay {l_delay}ms;\
    #        tc qdisc add dev r2-r1 parent 2: handle 3: htb default 10;\
    #        tc class add dev r2-r1 parent 3: classid 10 htb rate {l_bw}Mbit")

    #r_delay = 10
    #r_bw = 20
    #r2.cmd(f"tc qdisc del dev r2-h3 root;\
    #        tc qdisc add dev r2-h3 root handle 2: netem delay {r_delay}ms;\
    #        tc qdisc add dev r2-h3 parent 2: handle 3: htb default 10;\
    #        tc class add dev r2-h3 parent 3: classid 10 htb rate {r_bw}Mbit;")

    #r2.cmd(f"tc qdisc del dev r2-h4 root;\
    #        tc qdisc add dev r2-h4 root handle 2: netem delay {r_delay}ms;\
    #        tc qdisc add dev r2-h4 parent 2: handle 3: htb default 10;\
    #        tc class add dev r2-h4 parent 3: classid 10 htb rate {r_bw}Mbit;")

    # Start server
    server_cmd = "iperf3 -s"
    terms.append(openTerm(self, node=h3, cmd=server_cmd))
    terms.append(openTerm(self, node=h4, cmd=server_cmd))

    # Start monitor
    r1.sendCmd("tcpdump -i r1-r2 -w results/test/new-sit1-1.pcap")

    time.sleep(0.1)

    # Start client
    client_1_cmd = f"iperf3 -c 10.2.1.100 -n 5M"
    terms.append(openTerm(self, node=h1, cmd=client_1_cmd))
    client_2_cmd = f"iperf3 -c 10.2.2.100 -n 5M"
    terms.append(openTerm(self, node=h2, cmd=client_2_cmd))


def init_test(self, line):
    net = self.mn
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    r1 = net.get('r1')
    r2 = net.get('r2')

    # Disable hardware offloading
    h1.cmd("ethtool -k h1-r1 tso off;\
            ethtool -k h1-r1 gso off;\
            ethtool -k h1-r1 lro off;\
            ethtool -k h1-r1 gro off;\
            ethtool -k h1-r1 ufo off;")
    h2.cmd("ethtool -K h2-r1 tso off;\
            ethtool -K h2-r1 gso off;\
            ethtool -K h2-r1 lro off;\
            ethtool -K h2-r1 gro off;\
            ethtool -K h2-r1 ufo off;")

    # Traffic control
    l_delay = 0 # 0
    l_bw = 100   # 50
    r1.cmd(f"tc qdisc del dev r1-r2 root;\
            tc qdisc add dev r1-r2 root handle 2: netem delay {l_delay}ms;\
            tc qdisc add dev r1-r2 parent 2: handle 3: htb default 10;\
            tc class add dev r1-r2 parent 3: classid 10 htb rate {l_bw}Mbit;")

    h3_delay = 10 # 20
    h3_bw = 10    # 10
    h3_qsize = int((min(l_bw, h3_bw) * 125000) * (max(l_delay, h3_delay) * 0.001))  # BDP. 125000 = 1000000/8
    r2.cmd(f"tc qdisc del dev r2-h3 root;\
            tc qdisc add dev r2-h3 root handle 2: netem delay {h3_delay}ms;\
            tc qdisc add dev r2-h3 parent 2: handle 3: htb default 10;\
            tc class add dev r2-h3 parent 3: classid 10 htb rate {h3_bw}Mbit;\
            tc qdisc add dev r2-h3 parent 3:10 handle 11: bfifo limit {h3_qsize};")

    h4_delay = 20 # 20
    h4_bw = 5   # 10
    h4_qsize = int((min(l_bw, h4_bw) * 125000) * (max(l_delay, h4_delay) * 0.001))
    print(h3_qsize)
    print(h4_qsize)
    r2.cmd(f"tc qdisc del dev r2-h4 root;\
            tc qdisc add dev r2-h4 root handle 2: netem delay {h4_delay}ms;\
            tc qdisc add dev r2-h4 parent 2: handle 3: htb default 10;\
            tc class add dev r2-h4 parent 3: classid 10 htb rate {h4_bw}Mbit;\
            tc qdisc add dev r2-h4 parent 3:10 handle 11: bfifo limit {h4_qsize};")

    # Start server
    server_cmd = "iperf3 -s"
    terms.append(openTerm(self, node=h3, cmd=server_cmd))
    terms.append(openTerm(self, node=h4, cmd=server_cmd))

    # Start monitor
    r1.sendCmd("tcpdump -i r1-r2 -w results/test/two-flows-different-remote-combo.pcap")

    time.sleep(0.1)

    # Start client
    client_1_cmd = f"iperf3 -c 10.1.3.100 -n 5M" # -C cubic
    terms.append(openTerm(self, node=h1, cmd=client_1_cmd))
    client_2_cmd = f"iperf3 -c 10.1.4.100 -n 5M"  # -C cubic
    terms.append(openTerm(self, node=h2, cmd=client_2_cmd))


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

class Test(Topo):
    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost('h1', ip='10.1.1.100/24', defaultRoute='via 10.1.1.1')
        r  = self.addHost('r', ip='10.1.1.1/24', cls=LinuxRouter)
        h2 = self.addHost('h2', ip='10.2.2.100/24', defaultRoute='via 10.2.2.1')

        self.addLink(h1, r, intfName1='h1-r', intfName2='r-h1', cls=TCLink)
        self.addLink(h2, r, intfName1='h2-r', intfName2='r-h2', cls=TCLink,
                     params2={'ip': '10.2.2.1/24'})
        # local_bw = 10
        # remote_bw = 5
        # local_delay = 0
        # remote_delay = 10
        # bdp = min(local_bw, remote_bw) * 1000000 # b
        # rtt = ((local_delay+remote_delay)/1000) * 2
        # bdp = bdp * rtt    # b * s
        # bdp = bdp / 8      # b -> B
        # bdp = bdp // 1500  # MTU in Bytes
        # print(f"queue size: {bdp} packets")

def test_run(self, line):
    net = self.mn
    h1 = net.get('h1')
    h2 = net.get('h2')
    r  = net.get('r')

    # Disable hardware offloading  TODO: write about in report
    h1.cmd("ethtool -K h1-r tso off;\
            ethtool -K h1-r gso off;\
            ethtool -K h1-r lro off;\
            ethtool -K h1-r gro off;\
            ethtool -K h1-r ufo off;")

    r.cmd("tc qdisc del dev r-h2 root;\
           tc qdisc add dev r-h2 root handle 2: netem delay 20ms;\
           tc qdisc add dev r-h2 parent 2: handle 3: htb default 10;\
           tc class add dev r-h2 parent 3: classid 10 htb rate 10Mbit;\
           tc qdisc add dev r-h2 parent 3:10 handle 11: bfifo limit 25000;")

    # Server
    server_cmd = "iperf3 -s"
    terms.append(openTerm(self, node=h2, cmd=server_cmd))

    # Monitor
    r.sendCmd("tcpdump -i r-h1 -w results/test/new_test_r-h1-no-cc.pcap")

    time.sleep(0.1)

    # Client
    client_cmd = f"iperf3 -c 10.2.2.100 -n 5M"  # -C cubic
    terms.append(openTerm(self, node=h1, cmd=client_cmd))

class Virtual(Topo):

    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        s1 = self.addSwitch('s1')

        _loss = 0  # in %
        _delay = '100ms'
        _bw = 1 # Mbps
        _max_queue_size = 16 # bw*delay product
        self.addLink(h1, s1, bw=_bw)
        self.addLink(h2, s1, bw=_bw)
        self.addLink(s1, h3, bw=_bw, loss=_loss, delay=_delay, max_queue_size=_max_queue_size)


terms = []
def openTerm(self, node, cmd="zsh"):
    return node.popen(["xterm", "-hold", "-e", cmd])

def virt_test_nginx(self, line):
    net = self.mn
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    # Create webserver in terminal with h3's IP
    h3.cmd(f"python3 create_nginx_conf.py {h3.IP()}")
    time.sleep(1)

    send_cmd = "sudo nginx -c /etc/nginx/mininet_nginx_conf.conf &"
    h3.cmd(send_cmd)

    time.sleep(1)

    # Create recevier(s) in terminal
    tshark_cmd_h1 = f"sudo tshark -i {h1.defaultIntf()} -w test_nginx_h1-h3.pcap"
    tshark_cmd_h2 = f"sudo tshark -i {h2.defaultIntf()} -w test_nginx_h2-h3.pcap"
    terms.append(openTerm(self, node=h1, cmd=tshark_cmd_h1))
    terms.append(openTerm(self, node=h2, cmd=tshark_cmd_h2))

    # Wait for tshark to start
    time.sleep(1)

    # Query web server
    recv_cmd = f"curl http://{h3.IP()}/mininet_test/dog.png --output dog.png"
    terms.append(openTerm(self, node=h1, cmd=recv_cmd))
    terms.append(openTerm(self, node=h2, cmd=recv_cmd))

    # h3.cmd("sudo nginx -s stop")

def test_run_nginx(self, line):
    net = self.mn
    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')
    s2 = net.get('s2')

    # Server
    h2.cmd(f"python3 create_nginx_conf.py {h2.IP()}")
    time.sleep(0.1)

    send_cmd = "sudo nginx -c /etc/nginx/mininet_nginx_conf.conf &"
    h2.cmd(send_cmd)

    time.sleep(0.1)

    # Monitor
    s1_ifs = s1.connectionsTo(s2)
    terms.append(openTerm(self, node=s1, cmd=f"tcpdump -i {s1_ifs[0][0]} -w results/test/test_tcpdump_10-nginx"))

    # Client
    recv_cmd = f"curl http://{h2.IP()}/mininet_test/dog.png --output dog.png"
    terms.append(openTerm(self, node=h1, cmd=recv_cmd))

def virt_test(self, line):
    net = self.mn
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    server_cmd = "iperf3 -s -p 5201 -i 0.5"
    terms.append(openTerm(self, node=h3, cmd=server_cmd))
    time.sleep(0.1)
    terms.append(openTerm(self, node=h1, cmd="iperf3 -c 10.0.0.3 -p 5201 -n 10M -i 0.5 -C cubic | tee results/h1-h3"))
    terms.append(openTerm(self, node=h2, cmd="iperf3 -c 10.0.0.3 -p 5201 -n 10M -i 0.5 -C cubic | tee results/h2-h3"))

    h1.cmd("python plot.py h1-h3 h2-h3")
    


CLI.do_init_test = init_test
CLI.do_sit1_test = sit1_test
CLI.do_test_run = test_run
CLI.do_test_run_nginx = test_run_nginx
CLI.do_virt_test = virt_test
CLI.do_virt_test_nginx = virt_test_nginx

def do_EOF(self, line):
    for t in terms:
        os.kill(t.pid, signal.SIGKILL)
    return orig_EOF(self, line)

CLI.do_EOF = do_EOF

topos = {
        'virtual': ( lambda: Virtual() ),
        'sit1': ( lambda: Sit1() ),
        'test': ( lambda: Test() ),
        'fulltopo': ( lambda: FullTopo() ),
        'sit1topo': ( lambda: Sit1Topo() ),
}
