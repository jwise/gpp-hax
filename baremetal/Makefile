SRCS = main.c cmsis/src/core_cm3.c cmsis/src/cr_startup_lpc177x_8x.c cmsis/src/system_LPC177x_8x.c drivers/src/lpc177x_8x_uart.c drivers/src/lpc177x_8x_clkpwr.c drivers/src/lpc177x_8x_gpio.c drivers/src/lpc177x_8x_pinsel.c
OUTNAME = img
CFLAGS = -Icmsis/inc -Idrivers/inc -mcpu=cortex-m3 -mthumb -g
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