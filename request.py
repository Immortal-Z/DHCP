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
This module generates the DHCP request packets and send them out from designated interface.

The transaction ID, offered IP address, client MAC address and DHCP server identifier are collected from the DHCP offer
packet. Each DHCP request packet is unique and associated with one DHCP offer packet.

Function:

dhcp_request() -- generate a DHCP request packet which using specific fields collected from DHCP offer packet.
"""

import socket
import struct
import random
import checksum


def dhcp_request(_trans_id, _offered_addr, _client_mac, _server_addr):
    """
    Generate a DHCP request packet which using specific fields collected from DHCP offer packet.

    Working Principle:
    1> Build the layer 2(Ethernet) header.
    2> Build the layer 3(IP) header.
    3> Build the layer 4(UDP) header.
    4> Create the DHCP request data using some specific fields which collected from the DHCP offer packet.
    5> Calculate the checksum value for IP header and UDP header using checksum module(located at the same repository).
    6> Rebuild the IP and UDP header with real checksum value which calculated at step 5.
    7> Send the DHCP request packet from designated interface.

    :param _trans_id: The randomly number which generated when building DHCP discover packet. It is used to identify
                      different DHCP session.
    :param _offered_addr: The IP address which offered from DHCP server.
    :param _client_mac: The client's MAC address which sent the DHCP discover packet.
    :param _server_addr: The IP address of the server which sent the DHCP offer packet.
    """

    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    raw_socket.bind(('ens33', socket.htons(0x0800)))    # Interface name may vary with the computer.

    # Layer 2 Header
    src_mac = b'\xaa\xaa\xaa\xaa\xaa\xaa'
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    protocol = b'\x08\x00'

    # Layer 3 Header
    version = 4
    ihl = 5
    version_ihl = (version << 4) + ihl
    tos = 0
    total_len = 284
    ip_id = random.randint(0, 65535)
    flag = 0
    offset = 0
    flag_offset = (flag << 13) + offset     # Combine the flag filed and offset filed into two bytes.
    ttl = 255
    ip_protocol = socket.IPPROTO_UDP
    ip_checksum = 0                         # Checksum is set to 0 temporary.
    src_addr = b'\x00\x00\x00\x00'
    dst_addr = b'\xff\xff\xff\xff'

    # Layer 4 Header
    src_port = 68
    dst_port = 67
    udp_len = 264
    udp_checksum = 0                        # Checksum is set to 0 temporary.

    # DHCP Discover
    opcode = 1
    hardware_type = 1
    hardware_addr_len = 6
    hops = 1
    trans_id = _trans_id
    sec_elapsed = 0
    bootp_flag = 0
    client_ip = b'\x00' * 4
    your_ip = _offered_addr
    server_ip = b'\x00' * 4
    relay_ip = b'\x00' * 4
    client_mac = _client_mac
    client_mac_padding = b'\x00' * 10
    server_name = b'\x00' * 64
    boot_file_name = b'\x00' * 128
    magic_cookie = b'\x63\x82\x53\x63'
    option_53 = b'\x35\x01\x03'
    option_50 = b'\x32\04' + _offered_addr
    option_54 = b'\x36\x04' + _server_addr
    option_255 = b'\xff'

    # Calculate Real IP & UDP Checksum
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_len, ip_id, flag_offset, ttl, ip_protocol,
                            ip_checksum, src_addr, dst_addr)
    udp_header = struct.pack('!4s4sBBHHHHHBBBB4sHH4s4s4s4s6s10s64s128s4s3s6s6ss', src_addr, dst_addr, 0, ip_protocol
                             , udp_len, src_port, dst_port, udp_len, udp_checksum, opcode, hardware_type,
                             hardware_addr_len, hops, trans_id, sec_elapsed, bootp_flag, client_ip, your_ip, server_ip,
                             relay_ip, client_mac, client_mac_padding, server_name, boot_file_name, magic_cookie,
                             option_53, option_50, option_54, option_255)
    udp_real_checksum = checksum.checksum(udp_header)
    ip_real_checksum = checksum.checksum(ip_header)

    # Generate Headers
    l2_l3_header = struct.pack('!6s6s2sBBHHHBBH4s4s', dst_mac, src_mac, protocol, version_ihl, tos, total_len, ip_id,
                               flag_offset, ttl, ip_protocol, ip_real_checksum, src_addr, dst_addr)
    real_udp_header = struct.pack('!HHHHBBBB4sHH4s4s4s4s6s10s64s128s4s3s6s6ss', src_port, dst_port, udp_len,
                                  udp_real_checksum, opcode, hardware_type, hardware_addr_len, hops, trans_id,
                                  sec_elapsed, bootp_flag, client_ip, your_ip, server_ip, relay_ip, client_mac,
                                  client_mac_padding, server_name, boot_file_name, magic_cookie, option_53, option_50,
                                  option_54, option_255)
    packet = l2_l3_header + real_udp_header
    raw_socket.send(packet)

if __name__ == '__main__':
    trans_id = b'\xf9\xcf\x18\x44'
    offered_addr = b'\x11' * 4
    client_mac = b'\xaa' * 6
    server_addr = b'\x11' * 3 + b'\x01'
    dhcp_request(trans_id, offered_addr, client_mac, server_addr)
