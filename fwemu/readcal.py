from construct import Struct, Const, Array, Int32ul, Int8ul
import construct
import json
import matplotlib.pyplot as plt
import numpy as np

calibs = open('sflash.bin', 'rb').read()[0x714000:0x714000+0x3700]
chs = []

cstruct = Struct(
    "sig1" / Int32ul, # Const(b"Liu\x00"),
    "pad0" / Array(24, Int8ul),
    "sig2" / Int32ul, # Const(b"\x00\x00\x55\xff"),
    "table_vout_dac_src" / Array(67, Int32ul),
    "table_vout_adc_src" / Array(67, Int32ul),
    "table_voltage_10uv" / Array(67, Int32ul),
    "table_iout_dac" / Array(33, Int32ul),
    "table_iout_adc" / Array(33, Int32ul),
    "table_current_ua" / Array(33, Int32ul),
    "unused_maybe" / Array(33, Int32ul),
    "tab4_unknown_data_parallel" / Array(33, Int32ul),
    "tab4_unknown_index_parallel" / Array(33, Int32ul),
    "table_vout_dac_load" / Array(34, Int32ul),
    "unused_maybe_2" / Array(33, Int32ul),
    "table_vout_adc_load" / Array(34, Int32ul),
    "unused_maybe_3" / Array(33, Int32ul),
    "table_voltage_10uv_load" / Array(34, Int32ul),
    "unused_maybe_4" / Array(33, Int32ul),
    "tab5_unknown_data_src" / Array(34, Int32ul),
    "unused_maybe_5" / Array(33, Int32ul),
    "tab5_unknown_index_src" / Array(34, Int32ul),
    "unused_maybe_6" / Array(33, Int32ul),
    "tab5_unknown_data_load" / Array(34, Int32ul),
    "unused_maybe_7" / Array(33, Int32ul),
    "tab5_unknown_index_load" / Array(34, Int32ul),
    "unused_maybe_8" / Array(34, Int32ul),
    "sig3" / Int32ul, # Const(b"\x5a\xff\x55\xaa"),
    "flags" / Array(2, Int32ul)
)

def plain(obj):
    if type(obj) == construct.ListContainer:
        return [plain(s) for s in list(obj)]
    if type(obj) == construct.Container:
        return {k: plain(v) for (k,v) in obj.items() if k != '_io'}
    return obj

chs = []
for ch in range(4):
    calib = calibs[:0xdc0]
    calibs = calibs[0xdc0:]
    cparse = cstruct.parse(calib)
    chs.append(plain(cparse))

print(json.dumps(chs))

fig,axs = plt.subplots(2,2, figsize =  (11,8.5))

ax = axs[0,0]
ax.plot(chs[0]['table_vout_dac_src'], np.array(chs[0]['table_voltage_10uv'], np.float32) * 1e-5)
ax.plot(chs[1]['table_vout_dac_src'], np.array(chs[1]['table_voltage_10uv'], np.float32) * 1e-5)
ax.plot(chs[2]['table_vout_dac_src'], np.array(chs[2]['table_voltage_10uv'], np.float32) * 1e-5)
ax.plot(chs[3]['table_vout_dac_src'], np.array(chs[3]['table_voltage_10uv'], np.float32) * 1e-5)
ax.plot(chs[0]['table_vout_dac_load'], np.array(chs[0]['table_voltage_10uv_load'], np.float32) * 1e-5)
ax.plot(chs[1]['table_vout_dac_load'], np.array(chs[1]['table_voltage_10uv_load'], np.float32) * 1e-5)
ax.legend(['ch1 src', 'ch2 src', 'ch3', 'ch4', 'ch1 load', 'ch2 load'])
ax.grid()
ax.set_xlim(0)
ax.set_ylim(0)
ax.set_ylabel('Output voltage')
ax.set_xlabel('DAC value')
ax.set_title('Voltage DAC curve')

ax = axs[0,1]
ax.plot(chs[0]['table_iout_dac'], np.array(chs[0]['table_current_ua'], np.float32) * 1e-6)
ax.plot(chs[1]['table_iout_dac'], np.array(chs[1]['table_current_ua'], np.float32) * 1e-6)
ax.plot(chs[2]['table_iout_dac'], np.array(chs[2]['table_current_ua'], np.float32) * 1e-6)
ax.plot(chs[3]['table_iout_dac'], np.array(chs[3]['table_current_ua'], np.float32) * 1e-6)
ax.legend(['ch1', 'ch2', 'ch3', 'ch4'])
ax.grid()
ax.set_xlim(0)
ax.set_ylim(0)
ax.set_ylabel('Output current')
ax.set_xlabel('DAC value')
ax.set_title('Current DAC curve')


ax = axs[1,0]
ax.plot(np.array(chs[0]['table_voltage_10uv'], np.float32) * 1e-5, chs[0]['table_vout_adc_src'])
ax.plot(np.array(chs[1]['table_voltage_10uv'], np.float32) * 1e-5, chs[1]['table_vout_adc_src'])
ax.plot(np.array(chs[2]['table_voltage_10uv'], np.float32) * 1e-5, chs[2]['table_vout_adc_src'])
ax.plot(np.array(chs[3]['table_voltage_10uv'], np.float32) * 1e-5, chs[3]['table_vout_adc_src'])
ax.legend(['ch1', 'ch2', 'ch3', 'ch4'])
ax.grid()
ax.set_xlim(0)
ax.set_ylim(0)
ax.set_ylabel('ADC value')
ax.set_xlabel('Input voltage')
ax.set_title('Voltage ADC curve')

ax = axs[1,1]
ax.plot(np.array(chs[0]['table_current_ua'], np.float32) * 1e-6, chs[0]['table_iout_adc'])
ax.plot(np.array(chs[1]['table_current_ua'], np.float32) * 1e-6, chs[1]['table_iout_adc'])
ax.plot(np.array(chs[2]['table_current_ua'], np.float32) * 1e-6, chs[2]['table_iout_adc'])
ax.plot(np.array(chs[3]['table_current_ua'], np.float32) * 1e-6, chs[3]['table_iout_adc'])
ax.legend(['ch1', 'ch2', 'ch3', 'ch4'])
ax.grid()
ax.set_xlim(0)
ax.set_ylim(0)
ax.set_ylabel('ADC value')
ax.set_xlabel('Input current')
ax.set_title('Current ADC curve')

plt.savefig('calib.pdf', dpi=300)
plt.show()