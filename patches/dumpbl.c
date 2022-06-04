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

void *malloc(int len)
{
	return malloc_annotated("", "", 0, len);
}

void entry() {
//	void *s = malloc_annotated(512);
	void *p = malloc(0x20000);
	ui_set_overlay_params(5, 0, 0);
	ui_set_overlay_text(*ui_modal_overlay, "writing flash to USB...");
	memcpy(p, 0x0, 0x20000);
	file_write("1:FLASH.BIN", p, 0x20000);
	ui_set_overlay_text(*ui_modal_overlay, "done!");
	free(p);
//	free(s);
}
