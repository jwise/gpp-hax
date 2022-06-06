import serial
import struct
import signal
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

pins = {}

for port in range(0,5):
    dir = read32(0x20098000 + 0x20 * port)
    state = read32(0x20098014 + 0x20 * port)
    for pin in range(0,32):
        iocon = read32(0x4002c000 + port * 0x80 + pin * 4)
        pins[(port,pin)] = { "dir": (dir >> pin) & 1, "state": (state >> pin) & 1, "iocon": iocon }
        print(f"P{port}.{pin:02d}: IOCON {iocon:08x}, dir {(dir >> pin) & 1}, state {(state >> pin) & 1}")

nonintr = True
def intr(sig, frame):
    global nonintr
    nonintr = False
signal.signal(signal.SIGINT, intr)

while nonintr:
    for port in range(0,5):
        state = read32(0x20098014 + 0x20 * port)
        for pin in range(0,32):
            if (pins[(port,pin)]["iocon"] & 7) != 0:
                continue
            if ((state >> pin) & 1) != pins[(port,pin)]["state"]:
                print(f"P{port}.{pin:02d} transitioned to {(state >> pin) & 1}")
                pins[(port,pin)]["state"] = ((state >> pin) & 1)

s.write(b'b')
