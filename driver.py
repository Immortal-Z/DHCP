#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao

# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

"""
This module is the main component of program, which can be considered as driver.

As the core module, it will call 'discover' module to generate designated amount of DHCP discover packets, and starting
monitor the port 68 which be used for DHCP client. Once got any DHCP offer packet, it will collect transaction ID,
offered IP address, client MAC address and DHCP server identifier from DHCP offer packet in order to generate DHCP
request packet using 'request module'.
"""

import socket
import discover
import request

discover_amount = input(r'How Many IP Address Do You Want: ')
for amount in range(int(discover_amount)):
    discover.dhcp_discover()

new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # Allowing IP address reusing.
new_socket.bind(('', 68))   # Monitoring all IP address associated with this host.

while True:
    data, addr = new_socket.recvfrom(2048)
    if data[242] == 2:  # Only take action against DHCP offer packet.
        trans_id = data[4:8]
        offered_addr = data[16:20]
        client_mac = data[28:34]
        server_addr = data[245:249]
        request.dhcp_request(trans_id, offered_addr, client_mac, server_addr)
