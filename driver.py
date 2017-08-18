#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
