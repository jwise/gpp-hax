SRCS = main.c fmt.c minilib.c ctype.c

SRCS += cmsis/src/core_cm3.c cmsis/src/cr_startup_lpc177x_8x.c cmsis/src/system_LPC177x_8x.c drivers/src/lpc177x_8x_uart.c drivers/src/lpc177x_8x_clkpwr.c drivers/src/lpc177x_8x_gpio.c drivers/src/lpc177x_8x_pinsel.c drivers/src/lpc177x_8x_emc.c drivers/src/lpc177x_8x_lcd.c

#SRCS_USB = usb_tinyusb.c tinyusb/src/class/msc/msc_host.c tinyusb/src/common/*.c tinyusb/src/host/*.c tinyusb-shim/hcd_lpc17_40.c tinyusb/src/tusb.c tinyusb/src/portable/ohci/ohci.c
SRCS_USB = usb_lpcusblib.c lpcusblib/Drivers/USB/Core/*.c lpcusblib/Drivers/USB/Core/HCD/*.c lpcusblib/Drivers/USB/Core/HCD/OHCI/*.c lpcusblib/Drivers/USB/Class/Host/*.c lpcusblib/Drivers/USB/Class/Common/*.c

SRCS += $(wildcard $(SRCS_USB))

OUTNAME = img
CFLAGS = -Icmsis/inc -Idrivers/inc -mcpu=cortex-m3 -mthumb -g -Os -Itinyusb/src -I. -D__LPC177X_8X__ -DUSB_HOST_ONLY
CROSS = arm-none-eabi-
LDS = gpp.lds

CC = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
OBJS = $(patsubst %.c,obj/%.o,$(SRCS))

obj/$(OUTNAME).bin: obj/$(OUTNAME).elf pad.py
	$(OBJCOPY) -O binary $< $@
	python3 pad.py $@

obj/$(OUTNAME).elf: $(OBJS) $(LDS)
	$(CC) -T$(LDS) -o $@ $(OBJS) -Wl,-Map=$(OUTNAME).map -nostdlib -mcpu=cortex-m3 -mthumb

obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)