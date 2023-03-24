#!/usr/bin/env python3
import sys

input = sys.argv[1].strip()

utf = []

for i in input:
    utf.append("\\u00" + hex(ord(i)).split('x')[1])

print(''.join([i for i in utf]))
