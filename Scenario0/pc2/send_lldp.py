#! /usr/bin/env python3

from scapy.all import *
from scapy.contrib import lldp
import subprocess
import time

mac_address = subprocess.check_output("ifconfig eth0| grep ether | awk '{print $2}'| tr -d '\n'", shell=True)

chassis_id = lldp.LLDPDUChassisID(subtype= 7 , id = mac_address)
port_id =  lldp.LLDPDUPortID(subtype= 7, id=b'0')
ttl = lldp.LLDPDUTimeToLive(ttl=1)
system_name = lldp.LLDPDUSystemName(system_name=b'host')
end = lldp.LLDPDUEndOfLLDPDU()

mac_lldp_multicast = '01:80:c2:00:00:0e'
eth_frame  = Ether(src=mac_address, dst=mac_lldp_multicast, type=0x88cc)
frame = eth_frame/chassis_id/port_id/ttl/system_name/end
Ether(str(frame))


for i in range(4):
    sendp(frame)
    print(frame)
    time.sleep(3)
