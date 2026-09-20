#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>

int main(int argc, const char **argv) {
    (void)argc; (void)argv;
    char s[8];
    char cmd[64];

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Enter your name: ");
    fflush(stdout);

    if (fgets(cmd, sizeof(cmd), stdin) != NULL) {
        if (strncmp(cmd, "LEAK", 4) == 0) {
            /* intentional leak of libc base via link_map */
            void *libc_handle = dlopen("libc.so.6", RTLD_LAZY);
            if (!libc_handle)
                libc_handle = dlopen(NULL, RTLD_LAZY);

            if (libc_handle) {
                struct link_map *lm = NULL;
                if (dlinfo(libc_handle, RTLD_DI_LINKMAP, &lm) == 0 && lm) {
                    printf("LEAKED: 0x%lx\n", (unsigned long)lm->l_addr);
                    fflush(stdout);
                }
                dlclose(libc_handle);
            }
        } else {
            printf("Hello ");
            printf(cmd);   /* format-string vuln (optional path) */
            fflush(stdout);
        }
    }

    printf("\nEnter your message: ");
    fflush(stdout);

    /* intentional BOF: s is 8 bytes, read up to 256 */
    fgets(s, 256, stdin);

    return 0;
}