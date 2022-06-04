#!/usr/bin/env python
from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import struct

UNPACK_BYTES = 0x41c0e+1
#unpack_bytes(0x73018, 0x10000000, 0x4654)

def hook_mem_access_function(uc, access, addr, sz, val, data):
    if access == UC_MEM_WRITE:
        print(f">>> {addr:08x} <- {val:08x}")
    else:
        print(f">>> {addr:08x} rd")


def main():
    with open("./GPPV117.BIN", "rb") as f:
        ARM32_CODE = f.read()
    
    BADASS = 0xBAD000

    # memory address where emulation starts
    ADDRESS    = 0xa000
    STACK = 0x7ac0000
    STACK_SZ = 0x10000

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(ADDRESS, 0x400000)
    mu.mem_write(ADDRESS, ARM32_CODE)
    mu.mem_map(STACK, 0x10000)
    mu.mem_map(0x10000000, 0x80000)
    mu.mem_map(0x20000000, 0x100000)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access_function, begin = 0x20000000, end = 0x21000000)
    
    mu.mem_map(BADASS, 0x10000)

    mu.reg_write(UC_ARM_REG_LR, BADASS)
    mu.reg_write(UC_ARM_REG_SP, STACK + int(STACK_SZ/2))
    mu.reg_write(UC_ARM_REG_R0, 0x73018)
    mu.reg_write(UC_ARM_REG_R1, 0x10000000)
    mu.reg_write(UC_ARM_REG_R2, 0x4654)
    mu.emu_start(UNPACK_BYTES, BADASS)
    
    with open('mem-init.bin', 'wb') as f:
        f.write(mu.mem_read(0x10000000, 0x80000))

    mu.reg_write(UC_ARM_REG_LR, BADASS)
    mu.reg_write(UC_ARM_REG_R0, 0x15)
    mu.reg_write(UC_ARM_REG_R1, 0x1)
    mu.emu_start(0xD48A + 1, BADASS)
    
    print(mu.mem_read(0x10000168, 4))

if __name__ == "__main__":
    main()
