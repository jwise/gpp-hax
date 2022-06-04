#ifndef _API_H
#define _API_H

extern void (*ui_set_overlay_params)(int, int, int);
extern void (*ui_set_overlay_text)(void *overlay, const char *s);
extern void (*ui_modal_and_wait)(const char *s);

#endif
