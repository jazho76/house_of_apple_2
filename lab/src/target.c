#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#define NFILES       10
#define OVERWRITE_SZ 0x1e0
#define SCRATCH_SZ   0x1000

static FILE *files[NFILES];

static ssize_t read_line(char *buf, size_t size)
{
    size_t i = 0;
    int eof = 1;
    while (i + 1 < size) {
        char c;
        ssize_t n = read(0, &c, 1);
        if (n < 0) {
            buf[i] = '\0';
            return -1;
        }
        if (n == 0)
            break;
        eof = 0;
        if (c == '\n')
            break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return eof ? -1 : (ssize_t)i;
}

static ssize_t read_full(void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(0, (unsigned char *)buf + got, n - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static long read_long(const char *prompt)
{
    char buf[64];
    printf("%s", prompt);
    if (read_line(buf, sizeof buf) < 0)
        exit(0);
    return strtol(buf, NULL, 0);
}

static int read_index(void)
{
    long i = read_long("slot [0-9]: ");
    if (i < 0 || i >= NFILES) {
        printf("[!] index out of range\n");
        return -1;
    }
    return (int)i;
}

static FILE *slot(int i)
{
    if (i < 0)
        return NULL;
    if (!files[i]) {
        printf("[!] slot %d is not open\n", i);
        return NULL;
    }
    return files[i];
}

static void hexdump(const unsigned char *p, size_t n)
{
    for (size_t off = 0; off < n; off += 16) {
        printf("  %04zx: ", off);
        for (size_t j = 0; j < 16; j++) {
            if (off + j < n)
                printf("%02x ", p[off + j]);
            else
                printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && off + j < n; j++) {
            unsigned char c = p[off + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
}

static void dump_file(FILE *f)
{
    static const struct {
        unsigned off;
        const char *name;
    } fields[] = {
        {0x00, "_flags"},          {0x08, "_IO_read_ptr"},
        {0x10, "_IO_read_end"},    {0x18, "_IO_read_base"},
        {0x20, "_IO_write_base"},  {0x28, "_IO_write_ptr"},
        {0x30, "_IO_write_end"},   {0x38, "_IO_buf_base"},
        {0x40, "_IO_buf_end"},     {0x48, "_IO_save_base"},
        {0x50, "_IO_backup_base"}, {0x58, "_IO_save_end"},
        {0x60, "_markers"},        {0x68, "_chain"},
        {0x70, "_fileno/_flags2"}, {0x78, "_old_offset"},
        {0x80, "_cur_column..."},  {0x88, "_lock"},
        {0x90, "_offset"},         {0x98, "_codecvt"},
        {0xa0, "_wide_data"},      {0xa8, "_freeres_list"},
        {0xb0, "_freeres_buf"},    {0xb8, "__pad5"},
        {0xc0, "_mode/_unused2"},  {0xd8, "vtable"},
    };
    unsigned char *base = (unsigned char *)f;

    printf("FILE @ %p\n", (void *)f);
    for (size_t i = 0; i < sizeof fields / sizeof *fields; i++) {
        unsigned long v = *(unsigned long *)(base + fields[i].off);
        printf("  +0x%03x  %-16s = 0x%016lx\n",
               fields[i].off, fields[i].name, v);
    }
}

static void overwrite(FILE *f, const char *name)
{
    printf("[*] overwriting %s\n", name);
    dump_file(f);
    printf("[*] reading up to 0x%x bytes over the struct...\n", OVERWRITE_SZ);
    ssize_t n = read(0, f, OVERWRITE_SZ);
    printf("[+] wrote %zd bytes over %s @ %p\n", n, name, (void *)f);
    dump_file(f);
}

static void op_fopen(void)
{
    int i = read_index();
    if (i < 0)
        return;
    char path[64];
    snprintf(path, sizeof path, "/tmp/filestruct_lab_%d", i);
    if (files[i])
        fclose(files[i]);
    files[i] = fopen(path, "w+");
    if (!files[i]) {
        printf("[!] fopen failed\n");
        return;
    }
    printf("[+] slot %d: fopen(\"%s\", \"w+\") = %p\n", i, path, (void *)files[i]);
}

static void op_fwrite(void)
{
    FILE *f = slot(read_index());
    if (!f)
        return;

    long len = read_long("length: ");

    if (len < 0 || len > SCRATCH_SZ)
        len = SCRATCH_SZ;

    unsigned char *buf = malloc(SCRATCH_SZ);
    printf("data: ");
    ssize_t got = read_full(buf, (size_t)len);
    size_t n = fwrite(buf, 1, (size_t)got, f);
    printf("[+] fwrite returned %zu\n", n);
    free(buf);
}

static void op_fread(void)
{
    FILE *f = slot(read_index());
    if (!f)
        return;

    long len = read_long("count: ");
    if (len < 0 || len > SCRATCH_SZ)
        len = SCRATCH_SZ;

    unsigned char *buf = calloc(1, SCRATCH_SZ);
    size_t n = fread(buf, 1, len, f);
    printf("[+] fread returned %zu\n", n);
    hexdump(buf, n);
    free(buf);
}

static void op_fclose(void)
{
    int i = read_index();
    FILE *f = slot(i);

    if (!f)
        return;

    int r = fclose(f);
    files[i] = NULL;
    printf("[+] fclose returned %d\n", r);
}

static void op_inspect(void)
{
    FILE *f = slot(read_index());

    if (!f)
        return;

    dump_file(f);
}

static void menu(void)
{
    printf("\n"
           "=== FILE structure lab ===\n"
           " 1) fopen(i)            6) overwrite_file(i)\n"
           " 2) fwrite(i)           7) overwrite_stdin\n"
           " 3) fread(i)            8) overwrite_stdout\n"
           " 4) fclose(i)           9) overwrite_stderr\n"
           " 5) inspect(i)          0) quit\n");
}

void win(void)
{
    static const char msg[] = "[win] control flow hijacked\n";
    write(1, msg, sizeof msg - 1);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    void *libc_printf = dlsym(RTLD_DEFAULT, "printf");
    Dl_info info;

    if (libc_printf && dladdr(libc_printf, &info))
        printf("libc base = %p\n", info.dli_fbase);

    for (;;) {
        menu();
        switch (read_long("> ")) {
            case 1: op_fopen();               break;
            case 2: op_fwrite();              break;
            case 3: op_fread();               break;
            case 4: op_fclose();              break;
            case 5: op_inspect();             break;
            case 6: {
                int i = read_index();
                if (i >= 0) {
                    char name[32];
                    snprintf(name, sizeof name, "files[%d]", i);
                    FILE *f = slot(i);
                    if (f)
                        overwrite(f, name);
                }
                break;
            }
            case 7: overwrite(stdin,  "stdin");  break;
            case 8: overwrite(stdout, "stdout"); break;
            case 9: overwrite(stderr, "stderr"); break;
            case 0: return 0;
            default: printf("[!] unknown choice\n"); break;
        }
    }
}

