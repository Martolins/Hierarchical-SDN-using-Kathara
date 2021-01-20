# Hierarchical-SDN-using-Kathara
Routing in a SDN Hierarchical Network using Katharà

## Prerequisites
1) Make sure you have the latest version of Katharà installed
2) You will need two docker images: one for hosts and one for controllers \
   To build images, go to the folder where the Dockefile is located and type
    ```
        $ docker build -t kathara/host .
        $ docker build -t kathara/sdncontroller .
    ```

## Run the lab
To run the lab go to the lab directory, open a terminal and type:
```
$ kathara lstart
```

When all containers are ready, starting with controller C0 up to controller Cn, type: 
```
$ ryu-manager ryu/app/l2_switch.py 
```
for each controller.

This will allow all controllers to start up so that they start doing topology discovery

To run hosts to send their LLDP packets, in the dedicated terminal type:
```
$ python3 send_lldp.py
```

## How to do a ping test
ARP is not used to avoid broadcast storms on this network.
So to perform a ping you need to know the mac address and ip address of each host. 
To do this type in the host terminal:
```
$ ifconfig eth0
```
To add a static entry in the ARP table use the command:
```
$ arp -s <ip-address> <mac-address>
```
Once you have provided that information you can ping: 
```
 $ ping <ip-address>
 ```

The first ping will involve the controllers, 
the second only the switches that will have the rule in the flow table.

If you want to navigate the flow table of a switch in its terminal type:
```
$ ovs-ofctl dump-flows <switch-name> -O OpenFlow13
```
