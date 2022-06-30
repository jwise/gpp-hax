#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "lpc177x_8x_uart.h"
#include "lpc177x_8x_pinsel.h"
#include "lpc177x_8x_gpio.h"
#include "lpc177x_8x_emc.h"
#include "lpc177x_8x_lcd.h"
#include "lpc177x_8x_clkpwr.h"
#include "lpc177x_8x_pwm.h"
#include "lpc177x_8x_ssp.h"

#include "ff.h"

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

void sflash_setup() {
	PINSEL_ConfigPin(2, 23, 0);
	GPIO_OutputValue(2, 1 << 23, 1);
	GPIO_SetDir(2, 1 << 23, 1);
	
	PINSEL_ConfigPin(2, 22, 2); /* SSP0 SCK */
	PINSEL_ConfigPin(2, 26, 2); /* SSP0 MISO */
	PINSEL_ConfigPin(2, 27, 2); /* SSP0 MOSI */
	
	SSP_CFG_Type cfg;
	SSP_ConfigStructInit(&cfg);
	SSP_Init(LPC_SSP0, &cfg);
	SSP_Cmd(LPC_SSP0, ENABLE);
	
	GPIO_OutputValue(2, 1 << 23, 0);
	for (int i = 0; i < 0x100; i++)
		asm volatile("nop");
	SSP_DATA_SETUP_Type setup = {};
	uint8_t dout[4] = { 0x9F, 0xA9, 0xA9, 0xA9 };
	uint8_t din [4];
	setup.tx_data = dout;
	setup.rx_data = din ;
	setup.length = 4;
	SSP_ReadWrite(LPC_SSP0, &setup, SSP_TRANSFER_POLLING);
	GPIO_OutputValue(2, 1 << 23, 1);
	for (int i = 0; i < 0x100; i++)
		asm volatile("nop");
	
	printf("SPI FLASH IDCODE: %02x %02x %02x\n", din[1], din[2], din[3]);
}

void sflash_read(uint32_t ad, uint8_t *da, uint32_t len) {
	GPIO_OutputValue(2, 1 << 23, 0);
	for (int i = 0; i < 0x100; i++)
		asm volatile("nop");
	SSP_DATA_SETUP_Type setup = {};
	uint8_t dout[4] = { 0x03, (ad >> 16) & 0xFF, (ad >> 8) & 0xFF, ad & 0xFF };
	setup.tx_data = dout;
	setup.rx_data = NULL;
	setup.length = 4;
	SSP_ReadWrite(LPC_SSP0, &setup, SSP_TRANSFER_POLLING);
	setup.tx_data = NULL;
	setup.rx_data = da;
	setup.length = len;
	SSP_ReadWrite(LPC_SSP0, &setup, SSP_TRANSFER_POLLING);
	GPIO_OutputValue(2, 1 << 23, 1);
	for (int i = 0; i < 0x100; i++)
		asm volatile("nop");
}

void sflash_dump() {
	static uint8_t buf[4096];
	
	FIL file;
	unsigned long c;
	if (f_open(&file, "0:/sflash.bin", FA_CREATE_ALWAYS | FA_WRITE) != FR_OK) {
		puts("failed to open sflash.bin");
		return;
	}
	printf("writing to USB...\n");
	for (int i = 0; i < 8*1024*1024; i += 4096) {
		sflash_read(i, buf, 4096);
		f_writen(&file, buf, 4096, &c);
		if ((i % 512*1024) == 0) {
			printf("%d\r", i);
			fflush(stdout);
		}
	}
	printf("\ndone\n");
	f_close(&file);
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
#ifdef REVA
	GPIO_OutputValue(1, 1 << 7, 0);
#else
	GPIO_OutputValue(1, 1 << 7, 1);
#endif
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

uint8_t pwmbuf[8192];
volatile uint32_t pwm_consp = 0;
volatile uint32_t pwm_prodp = 0;
uint32_t samples = 0;

uint16_t vidbuf[8192] __attribute__((section(".dram"))) __attribute__((aligned(8)));
uint32_t vid_consp = 0;
uint32_t vid_prodp = 0;

void PWM0_IRQHandler(void) {
	LPC_PWM0->IR = PWM_INTSTAT_MR0; /* do this immediately, lest we get a double IRQ */
	LPC_PWM0->MR2 = pwmbuf[pwm_consp] * (4096 / 256);
	LPC_PWM0->LER = PWM_LER_EN_MATCHn_LATCH(2);
	if (pwm_consp != pwm_prodp)
		pwm_consp++;
	if (pwm_consp > sizeof(pwmbuf))
		pwm_consp = 0;
	samples++;
}


#define AUDIO_HZ 14648

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
	printf("periclk %d, myargc %d, myargc %08x, bss %08x, _ebss %08x\n", CLKPWR_GetCLK(CLKPWR_CLKTYPE_PER), myargc, &myargc, &_bss, &_ebss);
	
	puts("EMC is awake");

	puts("lighting up the LCD...");
	lcd_setup();
	puts("LCD setup complete");
	
	puts("starting up USB...");
	usb_setup();
	puts("USB setup complete");
	
	puts("starting up SPI flash...");
	sflash_setup();
	sflash_dump();
	puts("SFLASH done");
	
	puts("setting up PWM...");
	PINSEL_ConfigPin(1, 3, 3);
	const static PWM_TIMERCFG_Type timercfg = {
		.PrescaleOption = PWM_TIMER_PRESCALE_TICKVAL,
		.PrescaleValue = 1 /* per_clk = 60MHz */
	};
	PWM_Init(0, PWM_MODE_TIMER, (void *)&timercfg);
	PWM_ChannelConfig(0, 2, PWM_CHANNEL_SINGLE_EDGE);
	PWM_MatchUpdate(0, 0, 4096, PWM_MATCH_UPDATE_NOW); /* 14648.438 Hz */
	PWM_MatchUpdate(0, 2, 0, PWM_MATCH_UPDATE_NOW);
	const static PWM_MATCHCFG_Type match0 = {
		.MatchChannel = 0,
		.IntOnMatch = ENABLE,
		.StopOnMatch = DISABLE,
		.ResetOnMatch = ENABLE,
	};
	PWM_ConfigMatch(0, (PWM_MATCHCFG_Type *)&match0);
	const static PWM_MATCHCFG_Type match2 = {
		.MatchChannel = 2,
		.IntOnMatch = DISABLE,
		.StopOnMatch = DISABLE,
		.ResetOnMatch = DISABLE,
	};
	PWM_ConfigMatch(0, (PWM_MATCHCFG_Type *)&match2);

	PWM_ResetCounter(0);
	PWM_CounterCmd(0, ENABLE);
	PWM_ChannelCmd(0, 2, ENABLE);
	NVIC_EnableIRQ(PWM0_IRQn);
	puts("PWM init complete");
	
	FIL afile, vfile;
	if (f_open(&afile, "0:/audio.u8", FA_OPEN_EXISTING | FA_READ) != FR_OK) {
		puts("failed to open audio.u8");
	}
	if (f_open(&vfile, "0:/video.rle", FA_OPEN_EXISTING | FA_READ) != FR_OK) {
		puts("failed to open video.rle");
	}
	
	uint16_t next_words;
	long rdrv;
	f_readn(&vfile, &next_words, 2, &rdrv);
	
	PWM_Cmd(0, ENABLE);
	int starttime = board_millis();
	int frameno = 0;
	const int FPS = 23;
	while(1) {
		if ((pwm_prodp + 8192 - pwm_consp) % 8192 < 4096) {
			int maxn = 8192 - pwm_prodp;
			if (maxn > 4096)
				maxn = 4096;
			long n;
			f_readn(&afile, pwmbuf + pwm_prodp, maxn, &n);
			//printf("%d %d\n", pwm_prodp, n);
			pwm_prodp = (pwm_prodp + n) % 8192;
			if (n == 0)
				break;
		}

		if ((samples / (14648 / FPS)) > frameno) {
			frameno++;
			
			if (next_words == 0)
				break;
			vidbuf[0] = next_words;
			f_readn(&vfile, vidbuf + 1, next_words * 2 + 4, &rdrv);
			if (rdrv == next_words * 2 + 4) {
				next_words = vidbuf[2 + next_words];
			} else {
				next_words = 0;
			}
			
			uint16_t *obuf = lcd_fb;
			uint16_t n = vidbuf[0];
			uint16_t stat = vidbuf[1];
			for (int i = 0; i < vidbuf[0]; i++) {
				uint16_t len = vidbuf[i + 2];
				memset(obuf, stat ? 0xFF : 0x00, len * 2);
				obuf += len;
				stat = !stat;
			}
		}
		//printf("%d %d.", pwm_prodp, pwm_consp);
	}
	puts("done");
	
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
