# Running the topology
I am not sure why it is explained everywhere that you need to run `sudo python3.9 topology.py` on a VM when bash commands with Docker are provided and the code runs on every single operating system because of Docker.. I just used them.
To run my code, please run `sh start_topology.sh` and `sh start_controller.sh`.

# Implementation
I implemented all the functionality in all tasks, but did not bother much with flows, which I only implemented for forwarding and strict matching, no masks because of the firewall rules. Firewall rules make it hard to make generalisations because if we say generalise for a whole group of addresses, we would need to check every firewall rule for that datapath whether it forbids some address within that address range. This is possible, but difficult.

# Additional functionality
ICMP Host Unknown and Host Unreachable were implemented in a different way. 
Host Unknown:
 - uses routing table, no entry means host is unknown

Host Unreachable:
 - uses port status, if the link between the datapath and the device dies, that means the host is known as there is an arp/routing table entry for it, but is unreachable at the moment because it is disconnected. The code describes how to simulate that, so the port modified message gets sent to the controller