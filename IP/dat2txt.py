# -*- coding: utf-8 -*-

import sys

PY2 = sys.version_info[0] == 2

import functools
import os
import socket
import struct

_unpack_V = lambda b: struct.unpack("<L", b)
_unpack_N = lambda b: struct.unpack(">L", b)
_unpack_C = lambda b: struct.unpack("B", b)

ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
nip2int = lambda nipstr: struct.unpack('!I', nipstr)[0]
int2nip = lambda n: struct.pack('!I', n)

with open(os.path.join(os.path.dirname(__file__), "17monipdb.dat"), "rb") as f:
    dat = f.read()
    offset, = _unpack_N(dat[:4])
    max_comp_len = offset - 1028
    index = dat[4:offset]

    index_offset = index_length = 0
    start = 1024
    old_nip = socket.inet_aton('1.0.0.0')
    while start < max_comp_len:
        new_nip = index[start:start + 4]

        index_offset, = _unpack_V(
            index[start + 4:start + 7] + b'\0')
        if PY2:
            index_length, = _unpack_C(index[start + 7])
        else:
            index_length = index[start + 7]
        
        start += 8

        if index_offset == 0:
            old_nip = int2nip(nip2int(new_nip) + 1)
            continue

        res_offset = offset + index_offset - 1024
        print '%s %s %s' % (socket.inet_ntoa(old_nip), socket.inet_ntoa(new_nip), dat[res_offset:res_offset + index_length].decode("utf-8").strip().encode("utf-8"))
        if (start < max_comp_len):
            old_nip = int2nip(nip2int(new_nip) + 1)
