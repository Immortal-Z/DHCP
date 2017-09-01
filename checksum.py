#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao

# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

"""
This module calculates the checksum value within the IP/TCP/UDP/ICMP header.

IP Header Checksum
    --> Calculated based on all parts within the IP header. (Checksum value set to 0 during the calculating)
TCP/UDP Header Checksum
    --> Calculated based on pseudo header(assembled by source & destination IP addresses, 8 bits reserved section,
        IP protocol value and TCP/UDP length) plus all parts within the TCP/UDP header. (Checksum value set to 0 during
        the calculating)
ICMP Header Checksum
    --> Calculated based on all parts within the ICMP header. (Checksum value set to 0 during the calculating)

Function:

checksum() -- return the checksum value using integer format
"""


def checksum(byte_string):
    """
    Calculates the checksum value based on the byte_string parameter which pre-build by user.

    Detail Principle:
    1> Check the byte_string can be divided by 16 bits perfectly. If not, add one all zero byte at the end of the
       byte_string.
    2> Divide the byte_string into separate parts by 16 bits.
    3> Perform summation between parts created above and convert the result from decimal into hex.
    4> If the result is more than 0xffff(which means having more than "four digits"), then just simply divide result
       into two parts(last four digits as one part, the digits locates before last four part as another part) and
       perform summation between two parts, thus get the new result.
    5> Finally, perform bitwise complement operation on the result from step 3(or from step 4 when the step 3 result is
       more than 0xffff), and return the bitwise complement operation result.
    * For more information, please check RFC 1071.

    :param byte_string: The byte string which pre-calculated by user using struck.pack() function. Calculation is based
                        on the fields in the header or payload which should be used for checksum calculation. All fields
                        should be ordered properly.
    :return: Decimal integer as checksum value.
    """

    if len(byte_string) % 2 == 0:
        # Divided byte_string in to separate parts by 16 bits and put those parts into list.
        bit_block_list = [(('%02x' % x) + ('%02x' % y)) for x, y in zip(byte_string[0::2], byte_string[1::2])]
        first_sum = 0
        for value in bit_block_list:
            first_sum += eval('0x' + value)
        if len(hex(first_sum)) == 6:
            result = ~first_sum & 0xffff    # Bitwise complement operation
            return result
        elif len(hex(first_sum)) > 6:
            temp_hex = eval('0x' + hex(first_sum)[-4:]) + eval('0x' + hex(first_sum)[2:-4])
            result = ~temp_hex & 0xffff     # Bitwise complement operation
            return result
    else:
        byte_string += b'\x00'
        # Divided byte_string in to separate parts by 16 bits and put those parts into list.
        bit_block_list = [(('%02x' % x) + ('%02x' % y)) for x, y in zip(byte_string[0::2], byte_string[1::2])]
        first_sum = 0
        for value in bit_block_list:
            first_sum += eval('0x' + value)
        if len(hex(first_sum)) == 6:
            result = ~first_sum & 0xffff    # Bitwise complement operation
            return result
        elif len(hex(first_sum)) > 6:
            temp_hex = eval('0x' + hex(first_sum)[-4:]) + eval('0x' + hex(first_sum)[2:-4])
            result = ~temp_hex & 0xffff     # Bitwise complement operation
            return result

if __name__ == '__main__':
    import struct

    sample = input(r'Please Enter The Byte String: ')

    converted_sample = b''
    for part in sample.split(r'\x')[1:]:
        converted_sample += struct.pack('!B', eval('0x' + part))

    print(checksum(converted_sample))
