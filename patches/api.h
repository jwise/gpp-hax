#ifndef _API_H
#define _API_H

typedef void *overlay_hnd;

extern void (*ui_set_overlay_params)(int, int, int);
extern void (*ui_set_overlay_text)(overlay_hnd overlay, const char *s);
extern void (*ui_modal_and_wait)(const char *s);
extern void *(*malloc_annotated)(const char *file, const char *func, int line, int sz);
extern void (*free)(void *p);
extern void (*file_write)(const char *name, void *p, int len);
extern int (*GPPFilLoad)(const char *name, void **retp, int *outsz);
extern int (*sprintf)(char *dest, const char *s, ...);
extern overlay_hnd *ui_modal_overlay;

#endif
