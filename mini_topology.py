#!/usr/bin/env python3
#
# mini_topology_nat.py
#
#   - Creates h1, h2, h100, server, and cowrie (10.0.0.200) all plugged
#     into a single OpenFlow switch s1.
#   - Adds a Mininet-built NAT node so that every host can do `apt-get`,
#     git-clone, etc. (including cowrie).
#   - Starts a remote controller on 127.0.0.1:6633 (your POX Security_Controller).
#
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import os

def create_network():
    net = Mininet(controller=None)  # we’ll add a RemoteController manually

    # 1) Add a RemoteController (e.g. POX running on localhost:6633)
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # 2) Create a single OpenFlow switch
    s1 = net.addSwitch('s1')

    # 3) Create hosts (h1, h2, h100, server, cowrie)
    h1     = net.addHost('h1',     ip='10.0.0.1/24')
    h2     = net.addHost('h2',     ip='10.0.0.2/24')
    cowrie = net.addHost('cowrie', ip='10.0.0.200/24',mac='00:00:00:00:00:20')
    server = net.addHost('server', ip='10.0.0.10/24',mac='00:00:00:00:00:10')
    h100 = net.addHost('h100',     ip='10.0.0.100/24')
    
    
    dashboard = net.addHost('dashboard', ip='10.0.0.50/24')
    
    CONTROLLER_LOG_FILE='/home/zandar/pox/pox/controller.log'
    COWRIE_LOG_FILE='/home/cowrie/cowrie/var/log/cowrie/cowrie.json'
    
                                    


    
    # 4) Plug every host into switch s1
    for host in (h1, h2, cowrie, server, h100,dashboard):
        net.addLink(host, s1)

    # 5) Add a NAT node so that all hosts can reach the Internet
    #
    #    By calling net.addNAT() without extra keyword args, Mininet sets up
    #    a NAT that will masquerade any 10.0.0.0/24 traffic out your real
    #    interface. Inside 'cowrie', 'h1', etc., you can then do apt-get, git clone, etc.
    #
    nat = net.addNAT('nat0',ip='10.0.0.6/24')
    net.addLink(nat, s1)

    

    # 6) Start the network (switches, controller, links, etc.)
    net.start()
    
    info('*** Removing old Cowrie log files\n')
    cowrie.cmd('rm -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json*')
    
    

    # 7) Configure the NAT after starting (this writes the iptables rules)
    nat.configDefault()
    


    for host in (h1, h2, h100, server, cowrie, dashboard):
       host.cmd("ip route add default via 10.0.0.6")
       host.cmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
       host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
       host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")

       
    

    #starting https server on host:
    info('*** Starting HTTPS server on host "server"\n')
    server.cmd('mkdir -p /tmp/www')
    server.cmd('echo "Secure Server Running" > /tmp/www/index.html')
    server.cmd('cd /tmp/www && python3 -m http.server 443 &')
    info('*** HTTPS server is running on 10.0.0.10:443\n')   
    
    
    
    # Ensure dashboard can access log files
    dashboard.cmd(f'sudo chmod +r {CONTROLLER_LOG_FILE}')
    dashboard.cmd(f'sudo chmod +r {COWRIE_LOG_FILE}')
    
    
    
   
       
       
       
    
    
    info('*** Starting Cowrie Honeypot on host "cowrie"\n')

    # It's good practice to stop any old instances first.
    # The command is run as the 'cowrie' user, changes to the correct directory,
    # and then executes the stop script.
    cowrie.cmd('su - cowrie -c "cd /home/cowrie/cowrie && bin/cowrie stop"')

    # Add a small delay to ensure the process has time to stop cleanly
    
    time.sleep(2)
    # Now, start the service. The `bin/cowrie start` command is designed
    # to run as a background daemon, so the command will exit immediately
    # and your script will not hang.
    cowrie.cmd('su - cowrie -c "cd /home/cowrie/cowrie && bin/cowrie start"')
    info('*** Cowrie is up!.\n')
    
    info('*** Starting Cyber Guard dashboard server...\n')
    # Start the python server from the mounted /app directory.
    dashboard.cmd('python3 dashboard.py > /tmp/dashboard.log 2>&1 &')
    info('*** Dashboard is running. Access it at: http://10.0.0.50:5000\n')

    info('*** Mininet CLI started.\n')


    # 8) Drop into the Mininet CLI so you can do “xterm cowrie”, etc.
    CLI(net)

    # 9) When you exit the CLI, stop everything
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_network()
