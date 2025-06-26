
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import os

def create_network():
    net = Mininet(controller=None)  

    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    s1 = net.addSwitch('s1')

    h1     = net.addHost('h1',     ip='10.0.0.1/24')
    h2     = net.addHost('h2',     ip='10.0.0.2/24')
    cowrie = net.addHost('cowrie', ip='10.0.0.200/24',mac='00:00:00:00:00:20')
    server = net.addHost('server', ip='10.0.0.10/24',mac='00:00:00:00:00:10')
    h100 = net.addHost('h100',     ip='10.0.0.100/24')
    
    
    dashboard = net.addHost('dashboard', ip='10.0.0.50/24')
    
    CONTROLLER_LOG_FILE='/home/zandar/pox/pox/controller.log'
    COWRIE_LOG_FILE='/home/cowrie/cowrie/var/log/cowrie/cowrie.json'
    
                                    


    
    for host in (h1, h2, cowrie, server, h100,dashboard):
        net.addLink(host, s1)

    nat = net.addNAT('nat0',ip='10.0.0.6/24')
    net.addLink(nat, s1)

    net.start()
    
    info('*** Removing old Cowrie log files\n')
    cowrie.cmd('rm -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json*')
    
    

    nat.configDefault()
    


    for host in (h1, h2, h100, server, cowrie, dashboard):
       host.cmd("ip route add default via 10.0.0.6")
       host.cmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
       host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
       host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")

       
    

    info('*** Starting HTTPS server on host "server"\n')
    server.cmd('mkdir -p /tmp/www')
    server.cmd('echo "Secure Server Running" > /tmp/www/index.html')
    server.cmd('cd /tmp/www && python3 -m http.server 443 &')
    info('*** HTTPS server is running on 10.0.0.10:443\n')   
    
    
    
    dashboard.cmd(f'sudo chmod +r {CONTROLLER_LOG_FILE}')
    dashboard.cmd(f'sudo chmod +r {COWRIE_LOG_FILE}')
    
    
    info('*** Starting Cowrie Honeypot on host "cowrie"\n')

    cowrie.cmd('su - cowrie -c "cd /home/cowrie/cowrie && bin/cowrie stop"')

    
    time.sleep(2)
    cowrie.cmd('su - cowrie -c "cd /home/cowrie/cowrie && bin/cowrie start"')
    info('*** Cowrie is up!.\n')
    
    info('*** Starting Cyber Guard dashboard server...\n')
    dashboard.cmd('python3 dashboard.py > /tmp/dashboard.log 2>&1 &')
    info('*** Dashboard is running. Access it at: http://10.0.0.50:5000\n')

    info('*** Mininet CLI started.\n')


    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_network()
