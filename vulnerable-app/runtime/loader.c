#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <string.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void) {
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bpf file>\n", argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    bump_memlock_rlimit();

    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object '%s'\n", argv[1]);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object: %d\n", err);
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);

        if (!strncmp(sec, "kprobe/", 7)) {
            const char *fn = sec + 7;
            link = bpf_program__attach_kprobe(prog, false, fn);
        } else if (!strncmp(sec, "kretprobe/", 10)) {
            const char *fn = sec + 10;
            link = bpf_program__attach_kprobe(prog, true, fn);
        } else {
            fprintf(stderr, "skipping non-kprobe section: %s\n", sec);
            continue;
        }

        if (libbpf_get_error(link)) {
            err = libbpf_get_error(link);
            fprintf(stderr, "failed to attach %s: %d\n", sec, err);
        } else {
            printf("Attached section: %s\n", sec);
        }
    }

    printf("entering pause().\n");
    pause();
    return 0;
}

