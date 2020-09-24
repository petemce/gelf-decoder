#!//usr/bin/python
"""This will decode zlib compressed gelf, for gzip compressed
   use gzip and stringio
"""

import pyshark
import zlib
import binascii
import json
import pprint

cap = pyshark.LiveCapture('eth0', bpf_filter='port 12201')

for packet in cap.sniff_continuously(packet_count=1000):
    try:
        pprint.pprint(json.loads(zlib.decompress(binascii.unhexlify(packet.data.data))))
    except zlib.error:
        continue
