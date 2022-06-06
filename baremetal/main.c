#include "lpc177x_8x_uart.h"
#include "lpc177x_8x_pinsel.h"
#include "lpc177x_8x_gpio.h"

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
	char s[] = "Ligma balls!\r\n";
	
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
	
	while(1) {
		UART_Send(LPC_UART0, s, sizeof(s)-1, BLOCKING);
		PINSEL_ConfigPin(0, 24, 0);
		GPIO_SetDir(0, 1 << 24, 1);
		GPIO_OutputValue(0, 1 << 24, 1);
		break;
	}
}
