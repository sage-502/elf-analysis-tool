#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* ============================================================
 * ANSI 컬러 코드
 * ============================================================ */

#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_CYAN    "\033[36m"
#define COL_GREEN   "\033[32m"
#define COL_MAGENTA "\033[35m"
#define COL_WHITE   "\033[37m"
#define COL_GRAY    "\033[90m"

/* 터미널 컬러 지원 여부 (-n 옵션으로 비활성화) */
static int g_use_color = 1;
#define C(code)  (g_use_color ? (code) : "")

/* ============================================================
 * 취약 함수 데이터베이스
 * ============================================================ */

typedef enum {
    CAT_DANGEROUS = 0,
    CAT_FORMAT,
    CAT_MEMORY,
    CAT_SYSCALL,
    CAT_COUNT
} VulnCategory;

static const char *CATEGORY_NAMES[CAT_COUNT] = {
    "Dangerous C",
    "Format String",
    "Memory",
    "System Call"
};

static const char *CATEGORY_COLORS[CAT_COUNT] = {
    "\033[31m",   /* RED     - Dangerous */
    "\033[35m",   /* MAGENTA - Format    */
    "\033[36m",   /* CYAN    - Memory    */
    "\033[33m",   /* YELLOW  - Syscall   */
};

typedef struct {
    const char   *name;
    VulnCategory  category;
    int           severity;   /* 1=Low  2=Medium  3=High  4=Critical */
    const char   *reason;
    const char   *safe_alt;   /* 권장 대체 함수 */
} VulnFuncEntry;

static const VulnFuncEntry VULN_DB[] = {
    /* 위험 C 함수 */
    { "gets",     CAT_DANGEROUS, 4, "No bounds checking - always causes buffer overflow", "fgets()" },
    { "strcpy",   CAT_DANGEROUS, 3, "No bounds checking on destination buffer",           "strncpy() / strlcpy()" },
    { "strcat",   CAT_DANGEROUS, 3, "No bounds checking on destination buffer",           "strncat() / strlcat()" },
    { "sprintf",  CAT_DANGEROUS, 3, "No bounds checking on destination buffer",           "snprintf()" },
    { "vsprintf", CAT_DANGEROUS, 3, "No bounds checking on destination buffer",           "vsnprintf()" },
    { "scanf",    CAT_DANGEROUS, 3, "No bounds checking with %s specifier",               "fgets() + sscanf()" },
    { "sscanf",   CAT_DANGEROUS, 2, "Potential overflow with %s specifier",               "Use width-limited format" },
    { "strtok",   CAT_DANGEROUS, 1, "Not thread-safe, uses internal static buffer",       "strtok_r()" },
    { "mktemp",   CAT_DANGEROUS, 2, "Race condition in temp file creation",               "mkstemp()" },
    { "tmpnam",   CAT_DANGEROUS, 2, "Race condition in temp file creation",               "mkstemp()" },

    /* 포맷 스트링 관련 */
    { "printf",   CAT_FORMAT,    2, "Format string vuln if arg is user-controlled",       "Use literal format string" },
    { "fprintf",  CAT_FORMAT,    2, "Format string vuln if arg is user-controlled",       "Use literal format string" },
    { "vprintf",  CAT_FORMAT,    2, "Format string vuln if arg is user-controlled",       "Validate format string" },
    { "vfprintf", CAT_FORMAT,    2, "Format string vuln if arg is user-controlled",       "Validate format string" },
    { "syslog",   CAT_FORMAT,    2, "Format string vuln if arg is user-controlled",       "Use literal format string" },
    { "err",      CAT_FORMAT,    1, "Format string vuln if arg is user-controlled",       "Use literal format string" },
    { "warn",     CAT_FORMAT,    1, "Format string vuln if arg is user-controlled",       "Use literal format string" },

    /* 메모리 관련 */
    { "malloc",   CAT_MEMORY,    1, "NULL return unchecked may crash or overflow heap",   "Check return value always" },
    { "calloc",   CAT_MEMORY,    1, "Integer overflow in size calculation",               "Validate size before call" },
    { "realloc",  CAT_MEMORY,    2, "UAF if old pointer reused after failure",            "Assign to temp pointer first" },
    { "free",     CAT_MEMORY,    2, "Double-free or UAF if mismanaged",                   "Set pointer NULL after free" },
    { "alloca",   CAT_MEMORY,    3, "Stack overflow if size is user-controlled",          "Use malloc() with size check" },
    { "memcpy",   CAT_MEMORY,    2, "No overlap check; size must be validated",           "memmove() or validate size" },
    { "memmove",  CAT_MEMORY,    1, "Size must be validated",                             "Validate size before call" },
    { "memset",   CAT_MEMORY,    1, "Size must be validated",                             "Validate size before call" },
    { "bcopy",    CAT_MEMORY,    2, "Deprecated; no bounds check",                        "memcpy() / memmove()" },

    /* 시스템 호출 */
    { "system",   CAT_SYSCALL,   4, "Command injection if input is user-controlled",      "execve() with args array" },
    { "popen",    CAT_SYSCALL,   4, "Command injection if input is user-controlled",      "execve() with args array" },
    { "execl",    CAT_SYSCALL,   3, "Argument injection risk",                             "Validate all arguments" },
    { "execle",   CAT_SYSCALL,   3, "Argument injection risk",                             "Validate all arguments" },
    { "execlp",   CAT_SYSCALL,   3, "PATH hijacking risk",                                 "Use absolute path" },
    { "execv",    CAT_SYSCALL,   3, "Argument injection risk",                             "Validate all arguments" },
    { "execve",   CAT_SYSCALL,   3, "Argument injection risk",                             "Validate all arguments" },
    { "execvp",   CAT_SYSCALL,   3, "PATH hijacking risk",                                 "Use absolute path" },
    { "execvpe",  CAT_SYSCALL,   3, "PATH hijacking risk",                                 "Use absolute path" },
    { "putenv",   CAT_SYSCALL,   2, "Environment variable injection",                      "setenv() with validation" },
    { "setenv",   CAT_SYSCALL,   2, "Environment variable injection",                      "Validate key/value" },
};

#define VULN_DB_SIZE ((int)(sizeof(VULN_DB) / sizeof(VULN_DB[0])))

/* ============================================================
 * 탐색 결과 구조체
 * ============================================================ */

typedef struct VulnMatch {
    const VulnFuncEntry *entry;
    uint64_t             addr;
    struct VulnMatch    *next;
} VulnMatch;

typedef struct {
    VulnMatch *head;
    int        count;
    int        count_by_cat[CAT_COUNT];
    int        count_by_sev[5];   /* index 1~4 사용 */
} ScanResult;

/* ============================================================
 * ELF 파서 컨텍스트
 * ============================================================ */

typedef struct {
    uint8_t  *base;
    size_t    size;
    int       is64;
    char     *dynstr;
    size_t    dynstr_sz;
    uint8_t  *dynsym;
    size_t    dynsym_entsz;
    size_t    dynsym_cnt;
} ElfCtx;

/* ============================================================
 * 내부 유틸리티
 * ============================================================ */

static const VulnFuncEntry *lookup_vuln(const char *name) {
    for (int i = 0; i < VULN_DB_SIZE; i++)
        if (strcmp(VULN_DB[i].name, name) == 0)
            return &VULN_DB[i];
    return NULL;
}

static void result_add(ScanResult *res, const VulnFuncEntry *e, uint64_t addr) {
    VulnMatch *m = malloc(sizeof(*m));
    if (!m) return;
    m->entry = e; m->addr = addr; m->next = res->head;
    res->head = m; res->count++;
    res->count_by_cat[e->category]++;
    if (e->severity >= 1 && e->severity <= 4) res->count_by_sev[e->severity]++;
}

static void result_free(ScanResult *res) {
    VulnMatch *cur = res->head;
    while (cur) { VulnMatch *nx = cur->next; free(cur); cur = nx; }
    res->head = NULL;
}

/* ============================================================
 * ELF 파싱
 * ============================================================ */

static int parse_elf64(ElfCtx *ctx) {
    Elf64_Ehdr *e = (Elf64_Ehdr *)ctx->base;
    if (!e->e_shoff || !e->e_shnum) return 0;
    Elf64_Shdr *sh = (Elf64_Shdr *)(ctx->base + e->e_shoff);
    char *shstr = (char *)(ctx->base + sh[e->e_shstrndx].sh_offset);
    for (int i = 0; i < e->e_shnum; i++) {
        const char *n = shstr + sh[i].sh_name;
        if (!strcmp(n, ".dynstr")) {
            ctx->dynstr = (char *)(ctx->base + sh[i].sh_offset);
            ctx->dynstr_sz = sh[i].sh_size;
        }
        if (!strcmp(n, ".dynsym")) {
            ctx->dynsym = ctx->base + sh[i].sh_offset;
            ctx->dynsym_entsz = sh[i].sh_entsize ? sh[i].sh_entsize : sizeof(Elf64_Sym);
            ctx->dynsym_cnt = sh[i].sh_size / ctx->dynsym_entsz;
        }
    }
    return ctx->dynstr && ctx->dynsym;
}

static int parse_elf32(ElfCtx *ctx) {
    Elf32_Ehdr *e = (Elf32_Ehdr *)ctx->base;
    if (!e->e_shoff || !e->e_shnum) return 0;
    Elf32_Shdr *sh = (Elf32_Shdr *)(ctx->base + e->e_shoff);
    char *shstr = (char *)(ctx->base + sh[e->e_shstrndx].sh_offset);
    for (int i = 0; i < e->e_shnum; i++) {
        const char *n = shstr + sh[i].sh_name;
        if (!strcmp(n, ".dynstr")) {
            ctx->dynstr = (char *)(ctx->base + sh[i].sh_offset);
            ctx->dynstr_sz = sh[i].sh_size;
        }
        if (!strcmp(n, ".dynsym")) {
            ctx->dynsym = ctx->base + sh[i].sh_offset;
            ctx->dynsym_entsz = sh[i].sh_entsize ? sh[i].sh_entsize : sizeof(Elf32_Sym);
            ctx->dynsym_cnt = sh[i].sh_size / ctx->dynsym_entsz;
        }
    }
    return ctx->dynstr && ctx->dynsym;
}

/* ============================================================
 * 메인 탐색 함수
 * ============================================================ */

int elf_scan_vuln_funcs(const char *path, ScanResult *out) {
    if (!path || !out) return -1;
    memset(out, 0, sizeof(*out));

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return -2; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -3; }
    if (st.st_size < (off_t)EI_NIDENT) {
        fprintf(stderr, "File too small\n"); close(fd); return -4;
    }

    uint8_t *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror("mmap"); return -5; }

    if (memcmp(base, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        munmap(base, st.st_size); return -6;
    }

    ElfCtx ctx = { .base = base, .size = st.st_size };
    ctx.is64 = (base[EI_CLASS] == ELFCLASS64);

    if (!(ctx.is64 ? parse_elf64(&ctx) : parse_elf32(&ctx))) {
        fprintf(stderr, "Failed to locate .dynsym / .dynstr\n");
        munmap(base, st.st_size); return -7;
    }

    for (size_t i = 0; i < ctx.dynsym_cnt; i++) {
        uint64_t val = 0; uint32_t ni = 0;
        if (ctx.is64) {
            Elf64_Sym *s = (Elf64_Sym *)(ctx.dynsym + i * ctx.dynsym_entsz);
            ni = s->st_name; val = s->st_value;
        } else {
            Elf32_Sym *s = (Elf32_Sym *)(ctx.dynsym + i * ctx.dynsym_entsz);
            ni = s->st_name; val = s->st_value;
        }
        if (ni >= ctx.dynstr_sz) continue;
        const char *sym = ctx.dynstr + ni;
        if (!*sym) continue;
        const VulnFuncEntry *e = lookup_vuln(sym);
        if (e) result_add(out, e, val);
    }

    munmap(base, st.st_size);
    return 0;
}

/* ============================================================
 * 출력 함수
 * ============================================================ */

/* 심각도 → 레이블 */
static const char *sev_label(int s) {
    switch (s) {
        case 4: return "CRITICAL";
        case 3: return "HIGH    ";
        case 2: return "MEDIUM  ";
        default: return "LOW     ";
    }
}

/* 심각도 → 컬러 */
static const char *sev_color(int s) {
    switch (s) {
        case 4: return COL_RED;
        case 3: return COL_YELLOW;
        case 2: return COL_CYAN;
        default: return COL_GRAY;
    }
}

/* 반복 문자 출력 헬퍼 */
static void print_line(char ch, int n) {
    for (int i = 0; i < n; i++) putchar(ch);
    putchar('\n');
}

/* ──────────────────────────────────────────────────────────
 * print_banner()
 *   스캔 시작 헤더를 출력한다.
 *   path : 분석 대상 ELF 경로
 * ────────────────────────────────────────────────────────── */
void print_banner(const char *path) {
    printf("\n%s%s", C(COL_BOLD), C(COL_CYAN));
    print_line('=', 72);
    printf("  ELF Vulnerability Scanner\n");
    printf("  Target : %s\n", path);
    printf("%s%s", C(COL_RESET), C(COL_CYAN));
    print_line('=', 72);
    printf("%s\n", C(COL_RESET));
}

/* ──────────────────────────────────────────────────────────
 * print_result_table()
 *   탐색된 취약 함수 목록을 심각도 내림차순 테이블로 출력한다.
 *   결과가 없으면 "No vulnerable functions detected." 출력.
 * ────────────────────────────────────────────────────────── */
void print_result_table(const ScanResult *res) {
    if (res->count == 0) {
        printf("%s[+] No vulnerable functions detected.%s\n\n",
               C(COL_GREEN), C(COL_RESET));
        return;
    }

    /* 심각도 내림차순 정렬을 위한 임시 배열 */
    VulnMatch **arr = malloc(sizeof(VulnMatch *) * res->count);
    if (!arr) return;

    int idx = 0;
    for (VulnMatch *m = res->head; m; m = m->next)
        arr[idx++] = m;

    /* 버블 정렬 */
    for (int i = 0; i < idx - 1; i++)
        for (int j = i + 1; j < idx; j++)
            if (arr[j]->entry->severity > arr[i]->entry->severity) {
                VulnMatch *tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
            }

    /* 테이블 헤더 */
    printf("%s%s", C(COL_BOLD), C(COL_WHITE));
    printf("  %-10s  %-14s  %-14s  %-18s  %s\n",
           "SEVERITY", "CATEGORY", "FUNCTION", "ADDRESS", "REASON");
    printf("%s%s", C(COL_RESET), C(COL_GRAY));
    print_line('-', 90);
    printf("%s", C(COL_RESET));

    /* 각 행 출력 */
    for (int i = 0; i < idx; i++) {
        const VulnFuncEntry *e = arr[i]->entry;
        printf("  %s%-10s%s  %s%-14s%s  %s%-14s%s  0x%016llx  %s\n",
               g_use_color ? sev_color(e->severity)       : "", sev_label(e->severity),  C(COL_RESET),
               g_use_color ? CATEGORY_COLORS[e->category] : "", CATEGORY_NAMES[e->category], C(COL_RESET),
               C(COL_BOLD), e->name, C(COL_RESET),
               (unsigned long long)arr[i]->addr,
               e->reason);
    }

    printf("%s", C(COL_GRAY));
    print_line('-', 90);
    printf("%s\n", C(COL_RESET));

    free(arr);
}

/* ──────────────────────────────────────────────────────────
 * print_detail_report()
 *   함수별 상세 정보 (카테고리, 주소, 위험 이유, 권장 대체 함수)
 *   를 번호를 붙여 순서대로 출력한다.
 * ────────────────────────────────────────────────────────── */
void print_detail_report(const ScanResult *res) {
    if (res->count == 0) return;

    printf("%s%s[!] Detailed Report%s\n", C(COL_BOLD), C(COL_WHITE), C(COL_RESET));
    printf("%s", C(COL_GRAY));
    print_line('-', 72);
    printf("%s", C(COL_RESET));

    int no = 1;
    for (VulnMatch *m = res->head; m; m = m->next, no++) {
        const VulnFuncEntry *e = m->entry;
        printf("  %s[%02d]%s %s%s%s  —  %s%s%s\n",
               C(COL_BOLD), no, C(COL_RESET),
               C(COL_BOLD), e->name, C(COL_RESET),
               g_use_color ? sev_color(e->severity) : "", sev_label(e->severity), C(COL_RESET));
        printf("       Category : %s%s%s\n",
               g_use_color ? CATEGORY_COLORS[e->category] : "",
               CATEGORY_NAMES[e->category], C(COL_RESET));
        printf("       Address  : 0x%016llx\n", (unsigned long long)m->addr);
        printf("       Risk     : %s\n", e->reason);
        printf("       Safe Alt : %s%s%s\n\n",
               C(COL_GREEN), e->safe_alt, C(COL_RESET));
    }
}

/* ──────────────────────────────────────────────────────────
 * print_summary()
 *   전체 탐색 결과를 심각도별 / 카테고리별로 집계하여
 *   통계 요약을 출력한다.
 * ────────────────────────────────────────────────────────── */
void print_summary(const ScanResult *res) {
    printf("%s%s[*] Summary%s\n", C(COL_BOLD), C(COL_WHITE), C(COL_RESET));
    printf("%s", C(COL_GRAY));
    print_line('-', 72);
    printf("%s", C(COL_RESET));

    printf("  Total vulnerable functions : %s%s%d%s\n\n",
           C(COL_BOLD),
           res->count > 0 ? C(COL_RED) : C(COL_GREEN),
           res->count, C(COL_RESET));

    /* 심각도별 카운트 */
    static const char *sev_names[] = { "", "LOW", "MEDIUM", "HIGH", "CRITICAL" };
    printf("  By Severity:\n");
    for (int s = 4; s >= 1; s--) {
        if (!res->count_by_sev[s]) continue;
        printf("    %s%-10s%s : %d\n",
               g_use_color ? sev_color(s) : "", sev_names[s], C(COL_RESET),
               res->count_by_sev[s]);
    }

    /* 카테고리별 카운트 */
    printf("\n  By Category:\n");
    for (int c = 0; c < CAT_COUNT; c++) {
        if (!res->count_by_cat[c]) continue;
        printf("    %s%-14s%s : %d\n",
               g_use_color ? CATEGORY_COLORS[c] : "",
               CATEGORY_NAMES[c], C(COL_RESET),
               res->count_by_cat[c]);
    }

    printf("\n%s", C(COL_GRAY));
    print_line('=', 72);
    printf("%s\n", C(COL_RESET));
}

/* ──────────────────────────────────────────────────────────
 * print_report()  ← 외부에서 호출하는 최상위 출력 함수
 *   내부적으로 아래 순서로 출력한다:
 *     1. print_banner()
 *     2. print_result_table()
 *     3. print_detail_report()
 *     4. print_summary()
 * ────────────────────────────────────────────────────────── */
void print_report(const char *path, const ScanResult *res) {
    print_banner(path);
    print_result_table(res);
    print_detail_report(res);
    print_summary(res);
}

/* ============================================================
 * main
 * ============================================================ */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <elf_binary>\n"
        "Options:\n"
        "  -n   Disable color output\n"
        "  -h   Show this help\n",
        prog);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "nh")) != -1) {
        switch (opt) {
            case 'n': g_use_color = 0; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) { usage(argv[0]); return 1; }
    const char *path = argv[optind];

    ScanResult result;
    int ret = elf_scan_vuln_funcs(path, &result);
    if (ret < 0) {
        fprintf(stderr, "Scan failed (error code: %d)\n", ret);
        return 1;
    }

    print_report(path, &result);
    result_free(&result);
    return 0;
}
