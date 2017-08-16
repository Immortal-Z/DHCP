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

import socket
import struct
import random
import checksum


def dhcp_discover():
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    raw_socket.bind(('ens33', socket.htons(0x0800)))

    # Layer 2 Header
    src_mac = b'\xaa\xaa\xaa\xaa\xaa\xaa'
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    protocol = b'\x08\x00'

    # Layer 3 Header
    version = 4
    ihl = 5
    version_ihl = (version << 4) + ihl
    tos = 0
    total_len = 322
    ip_id = random.randint(0, 65535)
    flag = 0
    offset = 0
    flag_offset = (flag << 13) + offset
    ttl = 255
    ip_protocol = socket.IPPROTO_UDP
    ip_checksum = 0
    src_addr = b'\x00\x00\x00\x00'
    dst_addr = b'\xff\xff\xff\xff'

    # Layer 4 Header
    src_port = 68
    dst_port = 67
    udp_len = 302
    udp_checksum = 0

    # DHCP Discover Header
    opcode = 1
    hardware_type = 1
    hardware_addr_len = 6
    hops = 1
    trans_id = random.randint(1, pow(2, 32))
    sec_elapsed = 0
    bootp_flag = 0
    client_ip = b'\x00\x00\x00\x00'
    your_ip = b'\x00\x00\x00\x00'
    server_ip = b'\x00\x00\x00\x00'
    relay_ip = b'\x00\x00\x00\x00'
    client_mac = b''
    for num in range(7):
        temp_byte = random.randint(0, 255)
        client_mac += struct.pack('!B', temp_byte)
    client_mac_padding = b'\x00' * 10
    server_name = b'\x00' * 64
    boot_file_name = b'\x00' * 128
    magic_cookie = b'\x63\x82\x53\x63'
    option_53 = b'\x35\x01\x01'
    option_12 = b'\x0c\x08\x48\x79\x70\x65\x72\x69\x6f\x6e'
    option_55 = b'\x37\x0d\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a'
    option_255 = b'\xff'
    padding = b'\x00' * 25

    # Calculate Real IP & UDP Checksum
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_len, ip_id, flag_offset, ttl, ip_protocol,
                            ip_checksum, src_addr, dst_addr)
    udp_header = struct.pack('!4s4sBBHHHHHBBBBIHH4s4s4s4s6s10s64s128s4s3s10s15ss25s', src_addr, dst_addr, 0, ip_protocol
                             , udp_len, src_port, dst_port, udp_len, udp_checksum, opcode, hardware_type,
                             hardware_addr_len, hops, trans_id, sec_elapsed, bootp_flag, client_ip, your_ip, server_ip,
                             relay_ip, client_mac, client_mac_padding, server_name, boot_file_name, magic_cookie,
                             option_53, option_12, option_55, option_255, padding)
    udp_real_checksum = checksum.checksum(udp_header)
    ip_real_checksum = checksum.checksum(ip_header)

    # Generate Headers
    l2_l3_header = struct.pack('!6s6s2sBBHHHBBH4s4s', dst_mac, src_mac, protocol, version_ihl, tos, total_len, ip_id,
                               flag_offset, ttl, ip_protocol, ip_real_checksum, src_addr, dst_addr)
    real_udp_header = struct.pack('!HHHHBBBBIHH4s4s4s4s6s10s64s128s4s3s10s15ss25s', src_port, dst_port, udp_len,
                                  udp_real_checksum, opcode, hardware_type, hardware_addr_len, hops, trans_id,
                                  sec_elapsed, bootp_flag, client_ip, your_ip, server_ip, relay_ip, client_mac,
                                  client_mac_padding, server_name, boot_file_name, magic_cookie, option_53, option_12,
                                  option_55, option_255, padding)
    packet = l2_l3_header + real_udp_header
    raw_socket.send(packet)

if __name__ == '__main__':
    try:
        dhcp_discover()
        print('Packet Sent Succeed!')
    except:
        print('Packet Sent Failed!')
