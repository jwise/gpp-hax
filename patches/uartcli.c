#include "api.h"

#include "lpc177x_8x_libcfg_default.h"
#include "lpc177x_8x_uart.h"

typedef uint32_t size_t;

void readu(void *p, size_t n);
void writeu(const void *p, size_t n);
int puts(const char *c);
void puthex(uint32_t p);

int entry() {
    uint8_t cmd;
    uint8_t oldier;
    volatile uint32_t *adr;
    uint32_t da;
    puts("uartcli ready to lol\r\n");
    oldier = LPC_UART0->IER;
    LPC_UART0->IER = 0;
    while (1) {
        readu(&cmd, 1);
        switch (cmd) {
        case 'b':
            puts("goodbye!\r\n");
            goto done;
        case 'r':
            readu(&adr, 4);
            da = *adr;
            writeu(&da, 4);
            break;
        case 'w':
            readu(&adr, 4);
            readu(&da, 4);
            *adr = da;
            break;
        }
    }
done:
    LPC_UART0->IER = oldier;
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

