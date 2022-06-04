all: ligma.bin

CROSS ?= arm-none-eabi-
PLATFORM ?= v117
INBINARY ?= GPPV117.BIN

%.bin: %.elf
	python3 patch.py $(INBINARY) $< $@

%.elf: %.o $(PLATFORM).lds $(PLATFORM).o
	$(CROSS)ld -static -o $@ -T $(PLATFORM).lds $(PLATFORM).o $<

%.o: %.nb0
	$(CROSS)objcopy -I binary -O elf32-littlearm -B arm $< $@

%.o: %.c
	$(CROSS)gcc -march=armv7-a -mthumb -c -O -o $@ $<

%.o: %.S
	$(CROSS)gcc -march=armv7-a -mthumb -c -O -o $@ $<

