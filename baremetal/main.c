#include <stddef.h>
#include <stdarg.h>
#include <string.h>

#include "lpc177x_8x_uart.h"
#include "lpc177x_8x_pinsel.h"
#include "lpc177x_8x_gpio.h"
#include "lpc177x_8x_emc.h"
#include "lpc177x_8x_lcd.h"
#include "lpc177x_8x_clkpwr.h"

void puthex(uint32_t p) {
    const char *arr = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        write(1, arr + (p >> 28), 1);
        p <<= 4;
    }
}

/* We can't use the CMSIS setup routines because those map too many pins. */
void emc_setup() {
	/* Map pins. */
	PINSEL_ConfigPin(2, 16, 1); /* /CAS */
	PINSEL_ConfigPin(2, 17, 1); /* /RAS */
	PINSEL_ConfigPin(2, 18, 1); /* CLK0 */
	PINSEL_ConfigPin(2, 20, 1); /* DYCS0 */
	PINSEL_ConfigPin(2, 24, 1); /* CKE0 */
	PINSEL_ConfigPin(2, 28, 1); /* DQM0 */
	PINSEL_ConfigPin(2, 29, 1); /* DQM1 */
	PINSEL_ConfigPin(4, 24, 1); /* OE */
	PINSEL_ConfigPin(4, 25, 1); /* WE */
	PINSEL_ConfigPin(4, 30, 1); /* /CS0 */
	for (int i = 0; i < 16; i++)
		PINSEL_ConfigPin(3, i, 1); /* D[i] */
	for (int i = 0; i < 15; i++)
		PINSEL_ConfigPin(4, i, 1); /* A[i] */
	
	extern void EMC_PwrOn();
	EMC_PwrOn();

	LPC_EMC->Config = 0;
	
	/* turn on the DRAM */
	LPC_SC->EMCDLYCTL = 0x808; /* CMDDLY = 8, FBCLKDIV = 8 */
	
	LPC_EMC->DynamicConfig0 = 0x680; /* 4 banks, row length = 13, column length = 9 */
	LPC_EMC->DynamicRasCas0 = (3 << EMC_DYNAMIC_RASCAS_RASCFG_POS) | (3 << EMC_DYNAMIC_RASCAS_CASCFG_POS);
	LPC_EMC->DynamicReadConfig = 1;
	LPC_EMC->DynamicRP = 3;
	LPC_EMC->DynamicRAS = 6;
	LPC_EMC->DynamicSREX = 10;
	LPC_EMC->DynamicAPR = 2;
	LPC_EMC->DynamicDAL = 5;
	LPC_EMC->DynamicWR = 2;
	LPC_EMC->DynamicRC = 8;
	LPC_EMC->DynamicRFC = 8;
	LPC_EMC->DynamicXSR = 10;
	LPC_EMC->DynamicRRD = 2;
	LPC_EMC->DynamicMRD = 2;
	
	LPC_EMC->DynamicControl = 0x183; /* NOP */
	for (int i = 0; i < 0x8000; i++)
		asm volatile("nop");
	LPC_EMC->DynamicControl = 0x103; /* PALL */
	for (int i = 0; i < 0x100; i++)
		asm volatile("nop");
	LPC_EMC->DynamicRefresh = 66;
	LPC_EMC->DynamicControl = 0x83; /* MODE */
	*(volatile uint16_t *)0xa0033000;
	LPC_EMC->DynamicControl = 0x0; /* NORMAL */
	LPC_EMC->DynamicConfig0 = 0x80680; /* buffer on */

	for (int i = 0; i < 0x10000; i++)
		asm volatile("nop");
	
	/* turn on the SRAM */
	EMC_PwrOn();
	LPC_EMC->Config = 0;
	
	EMC_StaMemConfigMW(0, EMC_STATIC_CFG_MW_8BITS);
	EMC_StaMemConfigPB(0, /* All you have to do is be a little */ EMC_CFG_BYTELAND_READ_BITSLOW /* , a little bit late.  Just once. */);
	EMC_SetStaMemoryParameter(0, EMC_STA_MEM_WAITWEN, 5);
	EMC_SetStaMemoryParameter(0, EMC_STA_MEM_WAITOEN, 5);
	EMC_SetStaMemoryParameter(0, EMC_STA_MEM_WAITRD, 0x1f);
	EMC_SetStaMemoryParameter(0, EMC_STA_MEM_WAITPAGE, 5);
	EMC_SetStaMemoryParameter(0, EMC_STA_MEM_WAITWR, 0xf);
	EMC_SetStaMemoryParameter(0, EMC_STA_MEM_WAITTURN, 0xa);
}

uint16_t lcd_fb[480*272] __attribute__((section(".dram"))) __attribute__((aligned(8)));

void lcd_setup() {
	const LCD_Config_Type lcfg = {
		.hConfig = { .hfp = 2, .hbp = 2, .hsw = 41, .ppl = 480 },
		.vConfig = { .vfp = 3, .vbp = 3, .vsw = 10, .lpp = 272 },
		.polarity = { .cpl = 480, .active_high = 1, .acb = 0, },
		.panel_clk = 9000000,
		.lcd_bpp = LCD_BPP_16_565Mode,
		.lcd_type = LCD_TFT,
		.lcd_mono8 = 0,
		.lcd_dual = 0,
		.big_endian_byte = 0,
		.big_endian_pixel = 0,
		.lcd_panel_upper = lcd_fb,
		.lcd_panel_lower = lcd_fb,
		.lcd_palette = NULL
	};
	LCD_Init((LCD_Config_Type *)&lcfg);
	LCD_Enable(1);
	
	/* BGR565 */
	uint16_t *vbase = (uint16_t *)lcd_fb;
	for (int y = 0; y < 272; y++) {
		for (int x = 0; x < 480; x++) {
			uint8_t b = (x >> 1) ^ (y >> 1);
			uint8_t g = x ^ y;
			uint8_t r = (x >> 2) ^ (y >> 2);
			
			*vbase = (r & 0x1F) | ((g & 0x1F) << 5) | ((b & 0x1F) << 11);
			vbase++;
		}
	}
	
	/* backlight pwm_n */
	PINSEL_ConfigPin(2, 1, 0);
	GPIO_SetDir(2, 1 << 1, 1);
	GPIO_OutputValue(2, 1 << 1, 0);
	
	PINSEL_ConfigPin(2, 0, 0);
	GPIO_SetDir(2, 1 << 0, 1);
	GPIO_OutputValue(2, 1 << 0, 1);

	/* backlight master enable */
	PINSEL_ConfigPin(1, 7, 0);
	GPIO_SetDir(1, 1 << 7, 1);
	GPIO_OutputValue(1, 1 << 7, 1);
}

volatile uint32_t system_ticks = 0;
void SysTick_Handler (void)
{
	system_ticks++;
}

uint32_t board_millis(void)
{
	return system_ticks;
}

void mdelay(int ms) {
	int starttick = system_ticks;
	while (system_ticks < (starttick + ms))
		;
}

extern void debug_setup();
extern void usb_setup();
extern void usb_poll();

void main() {
	GPIO_Init();

	/* early init GPIO */
	PINSEL_ConfigPin(1, 5, 0); // fan_n
	GPIO_SetDir(1, 1 << 5, 1);
	GPIO_OutputValue(1, 1 << 5, 1);
	
	PINSEL_ConfigPin(5, 0, 0);
	GPIO_SetDir(5, 1 << 0, 1);
	GPIO_OutputValue(5, 1 << 0, 0);

	PINSEL_ConfigPin(5, 1, 0);
	GPIO_SetDir(5, 1 << 1, 1);
	GPIO_OutputValue(5, 1 << 1, 0);

	/* LED */
	PINSEL_ConfigPin(0, 18, 0);
	GPIO_SetDir(0, 1 << 18, 1);
	GPIO_OutputValue(0, 1 << 18, 1);

	emc_setup();
	extern char __dram_src, __dram_dest, __dram_size, __dram_bss, __dram_ebss;
	memcpy(&__dram_dest, &__dram_src, (uint32_t)&__dram_size);
	memset(&__dram_bss, 0, ((uint32_t)&__dram_ebss) - (uint32_t)&__dram_bss);

	debug_setup();
	
	PINSEL_ConfigPin(0, 21, 0);
	GPIO_SetDir(0, 1 << 21, 1);
	GPIO_OutputValue(0, 1 << 21, 1);
	
	extern int myargc, _bss, _ebss;
	printf("myargc %d, myargc %08x, bss %08x, _ebss %08x\n", myargc, &myargc, &_bss, &_ebss);
	
	puts("EMC is awake");
	
	puts("lighting up the LCD...");
	lcd_setup();
	puts("LCD setup complete");
	
	puts("starting up USB...");
	usb_setup();
	puts("USB setup complete");
	
	int last_flip = 0;
	int stat = 0;
	extern void D_DoomMain (void);
	D_DoomMain();
	while(1) {
		usb_poll();
		if ((board_millis() - last_flip) > 500) {
			GPIO_OutputValue(0, 1 << 21, stat);
			stat = !stat;
			last_flip = board_millis();
		}
	}
}
