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


def reg_hle(sym, fn):
    if type(sym) == str:
        addr = syms[sym]['addr']
    else:
        addr = sym
        symnames[addr] = 'FUCK'
    hle_syms[addr + 1] = fn

def hook_code(mu, address, size, user_data):
    if address+1 in hle_syms:
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

def hle_log(mu, r0, r1, r2, r3):
    address = mu.reg_read(UC_ARM_REG_PC)
    print(f">>> HLE {symnames[address]}({r0:08x}, {r1:08x}, {r2:08x}, {r3:08x}), lr = {mu.reg_read(UC_ARM_REG_LR):08x}")
    return r0
reg_hle('delay', hle_nop)
reg_hle('gpio_cfg_from_table', hle_nop)
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
    print(f">>> SPI flash cmd {r0:02x}")
    return 0
reg_hle('ssp0_txbyte', hle_ssp0_txbyte)

def hle_sflash_read_page(mu, adr, buf, sz, must_be_3):
    if must_be_3 != 3:
        raise RuntimeError('invalid arg3 for sflash_read_page')
    mu.mem_write(buf, sflash[adr:adr+sz])
    return 1
reg_hle('sflash_read_page', hle_sflash_read_page)

def hle_ui_set_active_framebuffer(mu, r0, r1, r2, r3):
    print(f">>> UI: window change to {r0:08x}")
    return r0
reg_hle('FUN_00018f5c', hle_ui_set_active_framebuffer)


def hle_uart_config_baud_int(mu, r0, r1, r2, r3):
    print(f">>> UART{r0} = {r1} baud")
    return 0
reg_hle('uart_config_baud_int', hle_uart_config_baud_int)

def hle_uart_xmit_cmd_1(mu, r0, r1, r2, r3):
    print(f">>> ch{r0} <- {r1:02x}")
    return 0
reg_hle('uart_xmit_cmd_1', hle_uart_xmit_cmd_1)

def hle_uart_xmit_cmd_4(mu, r0, r1, r2, r3):
    print(f">>> ch{r0} <- cmd {r1:02x}, payload {r2:06x}")
    return 0
reg_hle('uart_xmit_cmd_4', hle_uart_xmit_cmd_4)


def hle_get_hw_type(mu, r0, r1, r2, r3):
    return 3
reg_hle('get_hw_type', hle_get_hw_type)

def hle_gpio_set_from_table(mu, r0, r1, r2, r3):
    print(f">>> GPIO set({r0}) = {r1}, lr = {mu.reg_read(UC_ARM_REG_LR):08x}")
    return 0
reg_hle('gpio_set_from_table', hle_gpio_set_from_table)

def incr_wait_for_voltage_counter(mu):
    v = struct.unpack("<L", mu.mem_read(0x10004620, 4))[0]
    mu.mem_write(0x10004620, struct.pack("<L", v+1))

def incr_recalculate_timer(mu):
    v = struct.unpack("<L", mu.mem_read(0x10004614, 4))[0]
    mu.mem_write(0x10004614, struct.pack("<L", v+1))

uart_in = [b"", b"", b"", b""]
def uart_get_byte(mu, uart, addr):
    incr_wait_for_voltage_counter(mu)
    if len(uart_in[uart]) == 0:
#        print(f">>> UART read ch{uart} EMPTY")
        return 0
    by = uart_in[uart][0:1]
    print(f">>> UART read ch{uart} {by[0]:02x}")
    uart_in[uart] = uart_in[uart][1:]
    mu.mem_write(addr, by)
    return 1

def hle_uart1_get_byte(mu, r0, r1, r2, r3):
    return uart_get_byte(mu, 0, r0)
reg_hle('uart1_get_byte', hle_uart1_get_byte)
def hle_uart2_get_byte(mu, r0, r1, r2, r3):
    return uart_get_byte(mu, 1, r0)
reg_hle('uart2_get_byte', hle_uart2_get_byte)
def hle_uart3_get_byte(mu, r0, r1, r2, r3):
    return uart_get_byte(mu, 2, r0)
reg_hle('uart3_get_byte', hle_uart3_get_byte)
def hle_uart4_get_byte(mu, r0, r1, r2, r3):
    return uart_get_byte(mu, 3, r0)
reg_hle('uart4_get_byte', hle_uart4_get_byte)

# ... later
def hle_adc_ch_is_done(mu, r0, r1, r2, r3):
    return 0
reg_hle('adc_ch_is_done', hle_adc_ch_is_done)

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
reg_hle('timer0_wait_ticks', hle_log)
reg_hle(0xb4b6, hle_barf)


def watchpoint(uc, addr, f):
    def hook(uc, access, addr, sz, val, data):
        f(uc, addr, val)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook, begin = addr, end = addr)

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

def mainloop_once(mu):
    print(">>> main loop iter")
    mu.emu_start(0xad42+1, 0xadfc)
    print("    -> done")

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
    
    def watch_gppsta_nonpersist(mu, addr, val):
        if val == 0:
            return
        print(f"WRITE TO GPPSTA_NONPERSIST {val:08x}, PC = {mu.reg_read(UC_ARM_REG_PC):08x}")
        def watch_d4d5(mu, addr, val):
            print(f"WRITE TO D4D5, PC = {mu.reg_read(UC_ARM_REG_PC):08x}")
        watchpoint(mu, val + 0xA0, watch_d4d5)
        def watch_d9d8(mu, addr, val):
            print(f"WRITE TO D9D8, PC = {mu.reg_read(UC_ARM_REG_PC):08x}")
        watchpoint(mu, val + 0xB4, watch_d9d8)
        def watch_vadc(mu, addr, val):
            print(f"WRITE TO vadc0: {val}")
        watchpoint(mu, val + 0xe4, watch_vadc)
        def watch_vout_mv(mu, addr, val):
            print(f"WRITE TO vout_mv: {val}")
        watchpoint(mu, val + 0x0, watch_vout_mv)
    watchpoint(mu, 0x10004550, watch_gppsta_nonpersist)
    
    #mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access_function, begin = 0x20000000, end = 0x21000000)

    mu.reg_write(UC_ARM_REG_SP, STACK + int(STACK_SZ/2))
    callfn(mu, 'unpack_bytes', 0x73018, 0x10000000, 0x4654)
    callfn(mu, 'copy_words', 0x75554, 0x20000000, 0xC)
    callfn(mu, 'zero_words', 0x75554, 0x10004654, 0xb3c4)
    callfn(mu, 'zero_words', 0x75560, 0x2000000C, 0x42350)
    
    callfn(mu, 'GPPHard')
    callfn(mu, 'gpp_sw_init')
    
    callfn(mu, 'chan_load_set', 0, 1)
    callfn(mu, 'chan_load_set', 1, 1)
    callfn(mu, 'chan_load_set', 0, 0)
    callfn(mu, 'chan_load_set', 1, 0)
    callfn(mu, 'chan_load_set', 0, 2)
    callfn(mu, 'chan_load_set', 1, 2)
    callfn(mu, 'chan_load_set', 0, 0)
    callfn(mu, 'chan_load_set', 1, 0)
    callfn(mu, 'chan_load_set', 0, 3)
    callfn(mu, 'chan_load_set', 1, 3)
    callfn(mu, 'chan_load_set', 0, 0)
    callfn(mu, 'chan_load_set', 1, 0)
    
    callfn(mu, 'chan_set_bond_mode', 0, 1) # output series
    callfn(mu, 'chan_set_bond_mode', 0, 2) # output parallel
    callfn(mu, 'chan_set_bond_mode', 0, 0) # output normal
    
    callfn(mu, 'reset_timers_and_other_things')
    mainloop_once(mu)
    callfn(mu, 'channel_output_enable_outer_2', 0, 1)
    callfn(mu, 'channel_write_vset_mv', 0, 20000)
    callfn(mu, 'channel_write_iset_100ua', 0, 1000)
    uart_in[0] += b"\xE3"
    def cmd_4byte(ch, cmd, data):
        d = [cmd | (data >> 21), (data >> 14) & 0x7F, (data >> 7) & 0x7F, data & 0x7F]
        # uart_in[ch] += bytes(d)
        callfn(mu, 'uart_rx_multibyte_status', ch, d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3]) 
    cmd_4byte(0, 0xAE, 0x30000)
    incr_recalculate_timer(mu)
    mainloop_once(mu)
    incr_recalculate_timer(mu)
    mainloop_once(mu)
    incr_recalculate_timer(mu)
    mainloop_once(mu)
    incr_recalculate_timer(mu)
    mainloop_once(mu)
    incr_recalculate_timer(mu)
    mainloop_once(mu)
    incr_recalculate_timer(mu)
    mainloop_once(mu)

if __name__ == "__main__":
    main()
