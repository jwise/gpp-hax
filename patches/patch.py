from elftools.elf.elffile import ELFFile
import sys
import struct

SHF_ALLOC = 2

indata = bytearray(open(sys.argv[1], 'rb').read())

BASEAD = 0xa000

elf = ELFFile(open(sys.argv[2], 'rb'))
for sh in elf.iter_sections():
    if sh['sh_type'] == 'SHT_PROGBITS' and (sh['sh_flags'] & 2):
        ofs = sh['sh_addr']
        l = len(sh.data())
        print(f"{sh.name} loaded at {ofs:x}, {l} bytes")
        indata[ofs-BASEAD:ofs+l-BASEAD] = sh.data()

checksum = 0
for i in range(0,0x75ffc):
    checksum += indata[i]
checksum &= 0xFFFFFFFF
indata[0x75ffc:0x76000] = struct.pack("<L", checksum)

open(sys.argv[3], 'wb').write(indata)