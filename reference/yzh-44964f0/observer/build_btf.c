// SPDX-License-Identifier: GPL-2.0
// Build-time type export only: reads a BTF file without loading BPF programs.
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

static void emit(void *context, const char *format, va_list args)
{
    vfprintf(context, format, args);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: btf-header BTF_FILE\n");
        return 2;
    }
    struct btf *btf = btf__parse(argv[1], NULL);
    long error = libbpf_get_error(btf);
    if (!btf || error) {
        fprintf(stderr, "Cannot read BTF %s: %s\n", argv[1],
                strerror(error ? (int)-error : errno));
        return 1;
    }
    struct btf_dump *dump = btf_dump__new(btf, emit, stdout, NULL);
    error = libbpf_get_error(dump);
    if (!dump || error) {
        fprintf(stderr, "Cannot create BTF type exporter: %s\n",
                strerror(error ? (int)-error : errno));
        btf__free(btf);
        return 1;
    }
    puts("#ifndef __VMLINUX_H__\n#define __VMLINUX_H__\n"
         "#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n"
         "#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)\n"
         "#endif");
    for (__u32 id = 1; id < btf__type_cnt(btf); id++) {
        error = btf_dump__dump_type(dump, id);
        if (error) {
            fprintf(stderr, "Cannot export BTF type %u: %s\n", id, strerror((int)-error));
            break;
        }
    }
    puts("#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n#pragma clang attribute pop\n#endif\n#endif");
    if (fflush(stdout) || ferror(stdout))
        error = -EIO;
    btf_dump__free(dump);
    btf__free(btf);
    return error ? 1 : 0;
}
