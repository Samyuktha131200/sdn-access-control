 SDN-Based Access Control System

## Problem Statement
Allow only authorized hosts to communicate within the network using SDN and OpenFlow.

## Setup/Execution Steps
1. Install Mininet: sudo apt install mininet -y
2. Install Ryu: pip3 install ryu
3. Run controller: ~/.local/bin/ryu-manager access_control.py
4. Run Mininet: sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=single,3 --switch ovsk,protocols=OpenFlow13

## Test Scenarios
- h1 ping h2 → ALLOWED (whitelisted) ✅
- h1 ping h3 → BLOCKED (not whitelisted) ❌

## Expected Output
- 0% packet loss for allowed hosts
- 100% packet loss for blocked hosts
