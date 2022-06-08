#include <stddef.h>

#include "lpc177x_8x_uart.h"
#include "lpc177x_8x_pinsel.h"
#include "lpc177x_8x_gpio.h"
#include "lpc177x_8x_emc.h"

void *memcpy(char *dst, char *src, int n)
{
	char *dst0 = dst;
	while (n--)
		*(dst++) = *(src++);
	return dst0;
}

void *memset(char *b, int c, int len)
{
	char *b0 = b;
	while (len--)
		*(b++) = c;
	return b0;
}

#define UART_USR (LPC_UART0->LSR)
#define UART_BUF (LPC_UART0->THR)

void readu(void *_p, size_t n) {
    uint8_t *p = _p;
    while (n) {
        while (!(UART_USR & UART_LSR_RDR))
            ;
        *p = UART_BUF;
        p++;
        n--;
    }
}

void writeu(const void *_p, size_t n) {
    const uint8_t *p = _p;
    while (n) {
        while (!(UART_USR & UART_LSR_THRE))
            ;
        UART_BUF = *p;
        p++;
        n--;
    }
}

int puts(const char *c) {
    while (*c) {
        writeu((uint8_t *)c, 1);
        c++;
    }
    return 0;
}

void puthex(uint32_t p) {
    const char *arr = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        writeu(arr + (p >> 28), 1);
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

void main() {
	GPIO_Init();

	PINSEL_ConfigPin(0, 18, 0);
	GPIO_SetDir(0, 1 << 18, 1);
	GPIO_OutputValue(0, 1 << 18, 1);

	UART_CFG_Type ucfg = {
		.Baud_rate = 115200,
		.Parity = UART_PARITY_NONE,
		.Databits = UART_DATABIT_8,
		.Stopbits = UART_STOPBIT_1
	};
	
	/* UART0 connect */
	PINSEL_ConfigPin(0, 0, 2);
	PINSEL_ConfigPin(0, 1, 2);
	PINSEL_ConfigPin(0, 2, 1);
	PINSEL_ConfigPin(0, 3, 1);
//	PINSEL_SetPinMode(0, 0, PINSEL_BASICMODE_PLAINOUT);
//	PINSEL_SetPinMode(0, 1, PINSEL_BASICMODE_PLAINOUT);
	
	/* USB/serial mux */
	PINSEL_ConfigPin(1, 18, 0);
//	PINSEL_SetPinMode(1, 18, PINSEL_BASICMODE_PLAINOUT);
	GPIO_SetDir(1, 1 << 18, 1);
	GPIO_OutputValue(1, 1 << 18, 1);

	UART_Init(LPC_UART0, &ucfg);
	UART_TxCmd(LPC_UART0, ENABLE);
	
	PINSEL_ConfigPin(0, 21, 0);
	GPIO_SetDir(0, 1 << 21, 1);
	GPIO_OutputValue(0, 1 << 21, 1);
	
	puts("hello from before we turn on emc\r\n");
	emc_setup();
	
	puts("writing to EMC...\r\n");
	volatile uint32_t *extram = (uint32_t *)0xa0000000;
	for (int i = 0; i < 8*1024*1024 / 4; i++) {
		extram[i] = i; 
	}
	
	puts("reading from EMC...\r\n");
	int bad = 0;
	for (int i = 0; i < 8*1024*1024 / 4; i++) {
		if (extram[i] != i) {
			bad++;
			if (bad == 1) {
				puts("EMC failure: ");
				puthex(i);
				puts(" == ");
				puthex(extram[i]);
				puts("\r\n");
			}
		}
	}
	puts("EMC test: ");
	puthex(bad);
	puts(" failures\r\n");
	
	while(1)
		;
}
