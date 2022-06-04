#include "api.h"


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

void entry() {
	ui_modal_and_wait("Ligma balls!");
}
