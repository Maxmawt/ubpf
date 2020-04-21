/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <elf.h>
#include <math.h>
#include "ubpf.h"
#include "michelfralloc.h"

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/time.h>

void ubpf_set_register_offset(int x);
static void *readfile(const char *path, size_t maxlen, size_t *len);
static void register_functions(struct ubpf_vm *vm);
plugin_dynamic_memory_pool_t *mp;
void* mem;
size_t size;
int init_memory(void* memory);


static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "If --jit is given then the JIT compiler will be used.\n");
    fprintf(stderr, "\nOther options:\n");
    fprintf(stderr, "  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "mem", .val = 'm', .has_arg=1 },
        { .name = "jit", .val = 'j' },
        { .name = "register-offset", .val = 'r', .has_arg=1 },
        { }
    };

    const char *mem_filename = NULL;
    bool jit = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "hm:jr:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mem_filename = optarg;
            break;
        case 'j':
            jit = true;
            break;
        case 'r':
            ubpf_set_register_offset(atoi(optarg));
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }

    const char *code_filename = argv[optind];
    size_t code_len;
    void *code = readfile(code_filename, 1024*1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    size_t mem_len = 0;
    void *mem = NULL;
    if (mem_filename != NULL) {
        mem = readfile(mem_filename, 1024*1024, &mem_len);
        if (mem == NULL) {
            return 1;
        }
    }

    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    register_functions(vm);

    size = 200000000;

    mem = malloc(size);
    printf("mem malloced: %p\n", mem);
    init_memory(mem);
    printf("mem init, cxt: %p\n", mp);
    srandom(2);

    /* 
     * The ELF magic corresponds to an RSH instruction with an offset,
     * which is invalid.
     */
    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    char *errmsg;
    int rv;
    if (elf) {
        rv = ubpf_load_elf(vm, code, code_len, &errmsg, mem, size);
    } else {
        rv = ubpf_load(vm, code, code_len, &errmsg, mem, size);
    }

    printf("ubpf loaded\n");

    free(code);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    uint64_t ret;

    printf("before ubpf_exec\n");

    if (jit) {
        ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            return 1;
        }
        ret = fn(mem, size);
    } else {
        ret = ubpf_exec(vm, mem, size);
    }

    printf("after ubpf_exec\n");

    printf("0x%"PRIx64"\n", ret);

    ubpf_destroy(vm);

    free(mem);

    return 0;
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}

static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
    return ((uint64_t)a << 32) |
        ((uint32_t)b << 24) |
        ((uint32_t)c << 16) |
        ((uint16_t)d << 8) |
        e;
}

static void
trash_registers(void)
{
    /* Overwrite all caller-save registers */
    asm(
        "mov $0xf0, %rax;"
        "mov $0xf1, %rcx;"
        "mov $0xf2, %rdx;"
        "mov $0xf3, %rsi;"
        "mov $0xf4, %rdi;"
        "mov $0xf5, %r8;"
        "mov $0xf6, %r9;"
        "mov $0xf7, %r10;"
        "mov $0xf8, %r11;"
    );
}

static uint32_t
sqrti(uint32_t x)
{
    return sqrt(x);
}

void help_printf_uint32_t(uint32_t val) {
    printf("%u\n", val);
}

void help_printf_char(char c) {
    printf("%c\n", c);
}

void help_printf_str(char *s) {
    printf("%s\n", s);
}

void help_printf_ptr(void *p) {
    printf("%p\n", p);
}

void membound_fail(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    printf("Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr, stack_ptr);
}

int init_memory(void* memory) {
    mp = calloc(1, sizeof(plugin_dynamic_memory_pool_t));
    if(!mp) return -1;
    mp->memory_max_size = size;
    mp->memory_current_end = mp->memory_start = memory;
    return 0;
}

void * my_malloc(size_t size) {
    printf("my_malloc called\n");
    void* new_mem = michelfralloc(mp, size);
    printf("new_mem: %p\n",new_mem);
    return new_mem;
}

void print_result(char* str, int time) {
    printf("### %s run: %d ms\n", str, time);
}

int gettime(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int getrandom(){
    return random();
}

void my_memcpy(void* buf1, void* buf2, size_t len){
    memcpy(buf1, buf2, len);
}

static void
register_functions(struct ubpf_vm *vm)
{
    ubpf_register(vm, 0, "gather_bytes", gather_bytes);
    ubpf_register(vm, 1, "memfrob", memfrob);
    ubpf_register(vm, 2, "trash_registers", trash_registers);
    ubpf_register(vm, 3, "sqrti", sqrti);
    ubpf_register(vm, 4, "strcmp_ext", strcmp);
    ubpf_register(vm, 5, "memset", memset);
    ubpf_register(vm, 6, "socket", socket);
    ubpf_register(vm, 7, "bind", bind);
    ubpf_register(vm, 8, "recv", recv);
    ubpf_register(vm, 9, "malloc", malloc);
    ubpf_register(vm, 10, "help_printf_uint32_t", help_printf_uint32_t);
    ubpf_register(vm, 11, "help_printf_char", help_printf_char);
    ubpf_register(vm, 12, "help_printf_str", help_printf_str);
    ubpf_register(vm, 13, "help_printf_ptr", help_printf_ptr);
    ubpf_register(vm, 20, "my_malloc", my_malloc);
    ubpf_register(vm, 21, "print_result", print_result);
    ubpf_register(vm, 22, "gettime", gettime);
    ubpf_register(vm, 23, "getrandom", getrandom);
    ubpf_register(vm, 24, "memcpy", my_memcpy);
    ubpf_register(vm, 63, "membound_fail", membound_fail);
}
