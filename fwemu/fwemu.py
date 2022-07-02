#!/usr/bin/env python
from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import struct
import csv

with open('gppv117-syms.csv', 'r') as f:
    symcsv = list(csv.DictReader(f))
    syms = { s['Name']: { 'addr': int(s['Location'], 16), 'signature': s['Function Signature'], 'sz': int(s['Function Size'])} for s in symcsv }
    symnames = { int(s['Location'], 16): s['Name'] for s in symcsv }

RET_ADDR = 0xFF00FF00

hle_syms = {}

def callfn(mu, sym, *args):
    mu.reg_write(UC_ARM_REG_LR, RET_ADDR)
    # assume SP is already set appropriately
    if len(args) > 0:
        mu.reg_write(UC_ARM_REG_R0, args[0])
    if len(args) > 1:
        mu.reg_write(UC_ARM_REG_R1, args[1])
    if len(args) > 2:
        mu.reg_write(UC_ARM_REG_R2, args[2])
    if len(args) > 3:
        mu.reg_write(UC_ARM_REG_R3, args[3])
    if len(args) > 4:
        raise ValueError("too many args in call")
    print(f">>> call {sym}{args}")
    if type(sym) == str:
        addr = syms[sym]['addr'] + 1
    else:
        addr = sym
    mu.emu_start(addr, RET_ADDR)
    r0 = mu.reg_read(UC_ARM_REG_R0)
    print(f"    -> {r0:x}")
    return 0

def reg_hle(sym, fn):
    if type(sym) == str:
        addr = syms[sym]['addr']
    else:
        addr = sym
        symnames[addr] = 'FUCK'
    hle_syms[addr + 1] = fn

def hook_code(mu, address, size, user_data):
    if address+1 in hle_syms:
        print(f">>> HLE {symnames[address]}")
        rv = hle_syms[address+1](mu, mu.reg_read(UC_ARM_REG_R0), mu.reg_read(UC_ARM_REG_R1), mu.reg_read(UC_ARM_REG_R2), mu.reg_read(UC_ARM_REG_R3))
        mu.reg_write(UC_ARM_REG_R0, rv)

UNPACK_BYTES = 0x41c0e+1
#unpack_bytes(0x73018, 0x10000000, 0x4654)

def hook_mem_access_function(uc, access, addr, sz, val, data):
    if access == UC_MEM_WRITE:
        print(f">>> {addr:08x} <- {val:08x}")
    else:
        print(f">>> {addr:08x} rd")


def hook_mem_access_unmapped(uc, access, addr, sz, val, data):
    print(f"!!! unmapped access {addr:08x} from pc {uc.reg_read(UC_ARM_REG_PC):08x}, lr {uc.reg_read(UC_ARM_REG_LR):08x}")
    lol()

def hle_nop(mu, r0, r1, r2, r3):
    return r0
reg_hle('delay', hle_nop)
reg_hle('gpio_cfg_from_table', hle_nop)
reg_hle('gpio_set_from_table', hle_nop)
reg_hle('PINSEL_ConfigPin', hle_nop)
reg_hle('FUN_0000b71a', hle_nop) # some kind of pinsel
reg_hle('SystemInit', hle_nop)
reg_hle('PINSEL_SetPinMode', hle_nop)
reg_hle('GPIO_SetDir', hle_nop)
reg_hle('emc_init', hle_nop)
reg_hle('LCD_Init', hle_nop)
reg_hle('LCD_Enable', hle_nop)
reg_hle('channel_gpio_clr', hle_nop)
reg_hle('gpp_pwm_init', hle_nop)
reg_hle('FUN_0000c3da', hle_nop) # GPIB detect
reg_hle('FUN_0000c3f6', hle_nop) # enet detect
reg_hle('FUN_0000c09c', hle_nop) # systick init
reg_hle('usb_init', hle_nop)
reg_hle('adc_init', hle_nop)
reg_hle('FUN_00040be0', hle_nop) # some kind of IRQ init from gpp_sw_init
reg_hle('uart_enable_interrupts', hle_nop)
reg_hle('interrupt_disable_eint1', hle_nop)
reg_hle('interrupt_enable_eint1', hle_nop)
reg_hle('interrupt_set_enable', hle_nop)

sflash = open('./sflash.bin', 'rb').read()

def hle_ssp_setup_maybe(mu, r0, r1, r2, r3):
    if r0 != 0:
        raise RuntimeError(f'ssp_setup_maybe on implemented ssp {r0}')
    return r0
reg_hle('ssp_setup_maybe', hle_ssp_setup_maybe)

def hle_ssp0_txbyte(mu, r0, r1, r2, r3):
    print(f"    SPI flash cmd {r0:02x}")
    return 0
reg_hle('ssp0_txbyte', hle_ssp0_txbyte)

def hle_sflash_read_page(mu, adr, buf, sz, must_be_3):
    if must_be_3 != 3:
        raise RuntimeError('invalid arg3 for sflash_read_page')
    print(f"    SPI flash read {adr:08x}")
    mu.mem_write(buf, sflash[adr:adr+sz])
    return 1
reg_hle('sflash_read_page', hle_sflash_read_page)

def hle_set_lcd_base(mu, r0, r1, r2, r3):
    return r0
reg_hle('FUN_00018f5c', hle_set_lcd_base)


def hle_uart_config_baud_int(mu, r0, r1, r2, r3):
    print(f"    UART{r0} = {r1} baud")
    return 0
reg_hle('uart_config_baud_int', hle_uart_config_baud_int)

def hle_uart_xmit_cmd_1(mu, r0, r1, r2, r3):
    print(f"    ch{r0} <- {r1:02x}")
    return 0
reg_hle('uart_xmit_cmd_1', hle_uart_xmit_cmd_1)

def hle_uart_xmit_cmd_4(mu, r0, r1, r2, r3):
    print(f"    ch{r0} <- cmd {r1:02x}, payload {r2:06x}")
    return 0
reg_hle('uart_xmit_cmd_4', hle_uart_xmit_cmd_4)


def hle_get_hw_type(mu, r0, r1, r2, r3):
    return 3
reg_hle('get_hw_type', hle_get_hw_type)


no_barf = {
    0xa93b: True, # GPP_SW_INIT
    0x1c0dd: True, # buttons
}
def hle_barf(mu, r0, r1, r2, r3):
    if mu.reg_read(UC_ARM_REG_LR) in no_barf:
        return 0
    raise RuntimeError(f'bad function call from lr {mu.reg_read(UC_ARM_REG_LR):08x}')
reg_hle('GPIO_OutputValue', hle_barf)
reg_hle('GPIO_ReadValue', hle_barf)
reg_hle(0xb4b6, hle_barf)


def main():
    STACK = 0x7ac0000
    STACK_SZ = 0x10000

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(0x0, 0x100000)
    mu.mem_write(0x0,    open('./boot.bin', 'rb').read())
    mu.mem_write(0xa000, open("./GPPV117.bin", "rb").read())
    mu.mem_map(STACK, 0x10000)
    mu.mem_map(0x10000000, 64 * 1024) # int SRAM
    mu.mem_map(0x20000000, 512 * 1024) # ahb SRAM

    mu.mem_map(0xA0000000, 16 * 1024 * 1024) # DRAM

    #mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access_function, begin = 0x20000000, end = 0x21000000)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_access_unmapped)
    
    for hleadr in hle_syms:
        mu.mem_write(hleadr - 1, b"\x70\x47") # bx lr
        mu.hook_add(UC_HOOK_CODE, hook_code, begin = hleadr - 1, end = hleadr - 1)
    
    mu.mem_map(0xFF000000, 0x10000)

    mu.reg_write(UC_ARM_REG_SP, STACK + int(STACK_SZ/2))
    callfn(mu, 'unpack_bytes', 0x73018, 0x10000000, 0x4654)
    callfn(mu, 'copy_words', 0x75554, 0x20000000, 0xC)
    callfn(mu, 'zero_words', 0x75554, 0x10004654, 0xb3c4)
    callfn(mu, 'zero_words', 0x75560, 0x2000000C, 0x42350)
    
    callfn(mu, 'GPPHard')
    callfn(mu, 'gpp_sw_init')
    

if __name__ == "__main__":
    main()
