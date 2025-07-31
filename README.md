# Load-Balancer-Using-SDN

## Commands to run

### Terminal-1 Run Ryu controller
> ryu-manager load_balancer.py

 or

> ryu-manager simple_switch.py

### Terminal 2 Run Mininet OpenVswitch
> sudo python3 lb_topology.py

> s1 sudo python3 /home/mininet/msc-project/server_app.py &

> s2 sudo python3 /home/mininet/msc-project/server_app.py &

> s3 sudo python3 /home/mininet/msc-project/server_app.py &

### Terminal 3 Add a bridge network between Host to mininet
> sudo ip addr add 10.0.0.254/24 dev sw1

> sudo ip link set sw1 up