import sys
import struct

paddata = bytearray(b'\xff' * 0x76000)
indata = open(sys.argv[1], 'rb').read()
paddata[0:len(indata)] = indata
checksum = 0
for i in range(0,0x75ffc):
    checksum += paddata[i]
checksum &= 0xFFFFFFFF
paddata[0x75ffc:0x76000] = struct.pack("<L", checksum)
open(sys.argv[1], 'wb').write(paddata)