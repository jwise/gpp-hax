import serial
import struct
from time import sleep
import hashlib

s = serial.Serial(port = "/dev/ttyUSB4", baudrate=115200)
s.timeout = 0.5
s.read(10000)
s.timeout = None
#s.read_until(b'ready to lol\r\n')

def read32(adr):
    s.write(b'r')
    s.write(struct.pack('<L', adr))
    da = struct.unpack('<L', s.read(4))[0]
    #print(f"0x{adr:016x} -> 0x{da:08x}")
    return da

def write32(adr, da):
    s.write(b'w')
    s.write(struct.pack('<LL', adr, da))
    #print(f"0x{adr:016x} <- 0x{da:08x}")

print(f"PWM0TCR {read32(0x40014004):08x}")
print(f"PWM0TC  {read32(0x40014008):08x}")
print(f"PWM0PR  {read32(0x4001400c):08x}")
print(f"PWM0MCR {read32(0x40014014):08x}")
print(f"PWM0MR0 {read32(0x40014018):08x}")
print(f"PWM0MR1 {read32(0x4001401C):08x}")
print(f"PWM0MR2 {read32(0x40014020):08x}")
print(f"PWM0MR3 {read32(0x40014024):08x}")
print(f"PWM0MR4 {read32(0x40014040):08x}")
print(f"PWM0MR5 {read32(0x40014044):08x}")
print(f"PWM0MR6 {read32(0x40014048):08x}")
print(f"PWM0PCR {read32(0x4001404C):08x}")

print(f"PWM0TCR {read32(0x40018004):08x}")
print(f"PWM0TC  {read32(0x40018008):08x}")
print(f"PWM1PR  {read32(0x4001800c):08x}")
print(f"PWM1MCR {read32(0x40018014):08x}")
print(f"PWM1MR0 {read32(0x40018018):08x}")
print(f"PWM1MR1 {read32(0x4001801C):08x}")
print(f"PWM1MR2 {read32(0x40018020):08x}")
print(f"PWM1MR3 {read32(0x40018024):08x}")
print(f"PWM1MR4 {read32(0x40018040):08x}")
print(f"PWM1MR5 {read32(0x40018044):08x}")
print(f"PWM1MR6 {read32(0x40018048):08x}")
print(f"PWM1PCR {read32(0x4001804C):08x}")

write32(0x4001404C, read32(0x4001404C) | 0x400)
sleep(1)
write32(0x4001404C, read32(0x4001404C) & ~0x400)


s.write(b'b')
