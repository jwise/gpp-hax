SRCS = main.c stubs.c

SRCS += cmsis/src/core_cm3.c cmsis/src/cr_startup_lpc177x_8x.c cmsis/src/system_LPC177x_8x.c drivers/src/lpc177x_8x_uart.c drivers/src/lpc177x_8x_clkpwr.c drivers/src/lpc177x_8x_gpio.c drivers/src/lpc177x_8x_pinsel.c drivers/src/lpc177x_8x_emc.c drivers/src/lpc177x_8x_lcd.c drivers/src/lpc177x_8x_pwm.c drivers/src/lpc177x_8x_ssp.c

#SRCS_USB = usb_tinyusb.c tinyusb/src/class/msc/msc_host.c tinyusb/src/common/*.c tinyusb/src/host/*.c tinyusb-shim/hcd_lpc17_40.c tinyusb/src/tusb.c tinyusb/src/portable/ohci/ohci.c
SRCS_USB = usb_lpcusblib.c lpcusblib/Drivers/USB/Core/*.c lpcusblib/Drivers/USB/Core/HCD/*.c lpcusblib/Drivers/USB/Core/HCD/OHCI/*.c lpcusblib/Drivers/USB/Class/Host/*.c lpcusblib/Drivers/USB/Class/Common/*.c
#SRCS_USB = usb_usbhostlite.c usbhostlite/*.c

SRCS_DOOM = dummy.c am_map.c doomdef.c doomstat.c dstrings.c d_event.c d_items.c d_iwad.c d_loop.c d_main.c d_mode.c d_net.c f_finale.c f_wipe.c g_game.c hu_lib.c hu_stuff.c info.c i_cdmus.c i_endoom.c i_joystick.c i_main.c i_scale.c i_sound.c i_system.c i_timer.c i_video.c memio.c m_argv.c m_bbox.c m_cheat.c m_config.c m_controls.c m_fixed.c m_menu.c m_misc.c m_random.c p_ceilng.c p_doors.c p_enemy.c p_floor.c p_inter.c p_lights.c p_map.c p_maputl.c p_mobj.c p_plats.c p_pspr.c p_saveg.c p_setup.c p_sight.c p_spec.c p_switch.c p_telept.c p_tick.c p_user.c r_bsp.c r_data.c r_draw.c r_main.c r_plane.c r_segs.c r_sky.c r_things.c sha1.c sounds.c statdump.c st_lib.c st_stuff.c s_sound.c tables.c v_video.c wi_stuff.c w_checksum.c w_file.c w_file_stdc.c w_main.c w_wad.c z_zone.c

SRCS += $(wildcard $(SRCS_USB)) $(patsubst %.c,chocdoom/%.c,$(SRCS_DOOM))
SRCS += $(wildcard fatfs/*.c)

OUTNAME = img
CFLAGS = -Icmsis/inc -Idrivers/inc -mcpu=cortex-m3 -mthumb -g -Os -Itinyusb/src -I. -D__LPC177X_8X__ -DUSB_HOST_ONLY -Ifatfs/ --specs=nano.specs
CROSS = $(HOME)/gcc-arm-11.2-2022.02-x86_64-arm-none-eabi/bin/arm-none-eabi-
LDS = gpp.lds

CC = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
OBJS = $(patsubst %.c,obj/%.o,$(SRCS))

obj/$(OUTNAME).bin: obj/$(OUTNAME).elf pad.py
	$(OBJCOPY) -O binary $< $@
	python3 pad.py $@

obj/$(OUTNAME).elf: $(OBJS) $(LDS)
	$(CC) -T$(LDS) -o $@ $(OBJS) -Wl,-Map=obj/$(OUTNAME).map --specs=nano.specs -mcpu=cortex-m3 -mthumb -nostartfiles

obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)