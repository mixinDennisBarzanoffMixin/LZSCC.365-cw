from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, DefaultController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

import time

"""
Static Router Topology

This toplogy uses the Mininet Python API rather than the mn command line tool.
Thus, this topology file should be executed like any other python program.

Run: `sudo python3 topology.py`
"""


### Web server code -----
WEB_SERVER = '''
import json
from flask import Flask, request
app = Flask(__name__)
@app.route('/')
def cip():
    return json.dumps({
      "clientIP": request.remote_addr,
    }) 
if __name__ == '__main__':
    app.run(debug=False, port=80, host="0.0.0.0")
'''
# -----------------------

def run_webserver(node):
    node.cmd('web=`cat <<EOF\n{}\nEOF` && nohup python3 -c "$web" > /dev/null 2>&1 &'.format(WEB_SERVER))

def RouterNetwork(do_pingall=False, web_server=True, nat_testing=True):

    net = Mininet(switch=OVSSwitch, build=False, topo=None)

    # Add 2 controllers. One default for the switch, the second remote for the
    # routers.
    info("*** Adding Controllers\n")
    cs1 = net.addController("cs1", controller=DefaultController, port=6634) # switch
    cr1 = net.addController("cr1", controller=RemoteController, port=6633)  # routers

    # Add 2 "routers". As OvS switches are openflow enabled, these can act as
    # routers with the correct controller logic...
    info("*** Adding Routers\n")
    r1 = net.addSwitch("r1", cls=OVSKernelSwitch, dpid="0000000000000002")
    r2 = net.addSwitch("r2", cls=OVSKernelSwitch, dpid="0000000000000003")

    info("*** Adding Switches\n")
    s1 = net.addSwitch("s1", cls=OVSKernelSwitch, dpid="0000000000000001")

    info("*** Adding Hosts\n")
    hosts_l = [net.addHost("h%d" % n) for n in (1, 2)]
    hosts_r = [net.addHost("h%d" % n) for n in (3, 4)]
    host_web = net.addHost("web1")

    info("*** Adding Links\n")
    net.addLink(hosts_l[0], r1, port1=0, port2=1)
    net.addLink(hosts_l[1], r1, port1=0, port2=2)
    net.addLink(hosts_r[0], s1, port1=0, port2=1)
    net.addLink(hosts_r[1], s1, port1=0, port2=2)
    net.addLink(s1, r2, port1=3, port2=1)
    net.addLink(r1, r2, port1=3, port2=2)
    net.addLink(host_web, r2, port1=0, port2=3)

    info("*** Building Network\n")
    net.build()

    info("*** Setting Host Interface Values\n")

    hosts_l[0].intf("h1-eth0").setIP("10.0.0.140", 24)
    hosts_l[0].intf("h1-eth0").setMAC("00:aa:aa:aa:aa:aa")
    hosts_l[0].setARP("10.0.0.1", "00:bb:bb:bb:bb:aa")

    hosts_l[1].intf("h2-eth0").setIP("10.0.0.69", 24)
    hosts_l[1].intf("h2-eth0").setMAC("00:aa:aa:aa:aa:bb")
    hosts_l[1].setARP("10.0.0.1", "00:bb:bb:bb:bb:bb")

    hosts_r[0].intf("h3-eth0").setIP("112.97.37.9", 24)
    hosts_r[0].intf("h3-eth0").setMAC("00:cc:cc:cc:cc:aa")
    hosts_r[0].setARP("112.97.37.1", "00:dd:dd:dd:dd:aa")

    hosts_r[1].intf("h4-eth0").setIP("112.97.37.201", 24)
    hosts_r[1].intf("h4-eth0").setMAC("00:cc:cc:cc:cc:bb")
    hosts_r[1].setARP("112.97.37.1", "00:dd:dd:dd:dd:aa")

    host_web.intf("web1-eth0").setIP("1.2.3.4", 24)
    host_web.intf("web1-eth0").setMAC("00:ee:ee:ee:ee:aa")
    host_web.setARP("1.2.3.1", "00:dd:dd:dd:dd:cc")

    info("*** Setting Switch Interface Values\n")

    s1.intf("s1-eth1").setMAC("00:cc:cc:cc:cc:cc")
    s1.intf("s1-eth2").setMAC("00:cc:cc:cc:cc:dd")
    s1.intf("s1-eth3").setMAC("00:cc:cc:cc:cc:ee")

    info("*** Setting Router Interface Values\n")

    r1.intf("r1-eth1").setMAC("00:bb:bb:bb:bb:aa")
    r1.intf("r1-eth2").setMAC("00:bb:bb:bb:bb:bb")
    r1.intf("r1-eth3").setMAC("00:bb:bb:bb:bb:cc")

    r2.intf("r2-eth1").setMAC("00:dd:dd:dd:dd:aa")
    r2.intf("r2-eth2").setMAC("00:dd:dd:dd:dd:bb")
    r2.intf("r2-eth3").setMAC("00:dd:dd:dd:dd:cc")

    for controller in net.controllers:
        controller.start()

    # Start the switches and connect them to their appropriate controllers
    s1.start([cs1])
    r1.start([cr1])
    r2.start([cr1])

    info("*** Setting Default Routes\n")
    hosts_l[0].cmd("route add default gw 10.0.0.1 h1-eth0")
    hosts_l[1].cmd("route add default gw 10.0.0.1 h2-eth0")
    hosts_r[0].cmd("route add default gw 112.97.37.1 h3-eth0")
    hosts_r[1].cmd("route add default gw 112.97.37.1 h4-eth0")
    host_web.cmd("route add default gw 1.2.3.1 web1-eth0")

    if do_pingall:
        info("*** Testing Network...\n")
        net.pingAll()

    if web_server:
        info("*** Starting Web Server...\n")
        run_webserver(host_web)
    
    if nat_testing:
        info("*** Starting Host Web Servers...\n")
        for h in hosts_l + hosts_r:
            run_webserver(h)
        
    if nat_testing or web_server:
        time.sleep(10)


    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping Network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")  # for CLI output
    RouterNetwork(do_pingall=False)
