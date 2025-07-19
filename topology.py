# topology.py (Robust Version)

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def run_network():
    # 1. Create a Mininet object, but without a default controller
    net = Mininet(controller=None)

    # 2. Add a remote controller
    print("Adding a remote controller...")
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)

    # 3. Add hosts and switches
    print("Adding hosts...")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')

    print("Adding a switch...")
    s1 = net.addSwitch('s1')

    print("Creating links...")
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    # 4. Build the network
    print("Building network...")
    net.build()

    # 5. Start the controller(s)
    print("Starting controller(s)...")
    c0.start()

    # 6. Start the switch(es) and connect them to the controller
    print("Starting switch(es)...")
    s1.start([c0])
    
    # 7. Run the CLI
    print("Network is up. Running CLI...")
    CLI(net)

    # 8. Stop the network
    print("Stopping network...")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_network()