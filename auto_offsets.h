#ifndef AUTO_OFFSETS_H
#define AUTO_OFFSETS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    long offset_system;
    long offset_setuid;
    long offset_binsh;
    long offset_pop_rdi;
    long offset_ret_align;
    long offset_auto_leak;
    int page_size;
} LibcOffsets;

LibcOffsets get_auto_offsets(void);

#ifdef __cplusplus
}
#endif

#endif