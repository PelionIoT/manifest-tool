#!/usr/bin/python
import sys

lines = []
with open(sys.argv[1],'r') as f:
    for line in f:
        if '0x' in line:
            line = line.split('//')[0]
            lines.append(line.strip())

valstr = ' '.join(lines)
vals = [chr(int(x.strip(),16)) for x in valstr.split(',') if len(x.strip())]
valstr = b''.join(vals)

with open(sys.argv[2],'wb') as f:
    f.write(bytes(bytearray(vals)))
