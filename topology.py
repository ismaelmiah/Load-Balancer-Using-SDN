from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def run_lb_network():
    net = Mininet(controller=None)

    print("Adding a remote controller...")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    print("Adding hosts with SPECIFIC MACs...")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    s1 = net.addHost('s1', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    s2 = net.addHost('s2', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    s3 = net.addHost('s3', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    print("Adding a switch...")
    sw = net.addSwitch('sw1')

    print("Creating links...")
    net.addLink(h1, sw)
    net.addLink(s1, sw)
    net.addLink(s2, sw)
    net.addLink(s3, sw)

    print("Building network...")
    net.build()

    print("Starting controller(s)...")
    c0.start()

    print("Starting switch(es)...")
    sw.start([c0])
    
    print("Network is up. Running CLI...")
    CLI(net)

    print("Stopping network...")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_lb_network()