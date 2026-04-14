# SDN Host Discovery and Firewall using Ryu

##  Problem Statement
This project implements an SDN-based host discovery and firewall system using Ryu controller and Mininet.

##  Objectives
- Detect hosts in network
- Implement learning switch
- Apply flow rules (match-action)
- Block specific host (firewall)
- Analyze performance using ping and iperf

##  Tools Used
- Ryu Controller
- Mininet
- OpenFlow 1.3

##  Setup Steps

1. Start controller:
   ryu-manager host_discovery.py
2. Run Mininet:
   sudo mn --topo single,4 --controller remote
   
##  Test Cases
3. Allowed Communication
h1 ping h2
Result: Successful
4.Blocked Communication
 h4 ping h1
 Result: 100% packet loss
5. Flow Rules
Check flow rules:
sudo ovs-ofctl dump-flows s1
6.Firewall rule:
priority=100, eth_src=00:00:00:00:00:04 actions=drop
7.Performance Testing
iperf

## Screenshots
All screenshots are available in the `screenshots/` folder.

##  Conclusion
This project demonstrates SDN-based control, host discovery, and firewall implementation using Ryu.

