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
 * 취약 함수 데이터베이스
 * ============================================================ */

typedef enum {
    CAT_DANGEROUS = 0,   // 위험 C 함수
    CAT_FORMAT,          // 포맷 스트링 관련
    CAT_MEMORY,          // 메모리 관련
    CAT_SYSCALL,         // 시스템 호출
    CAT_COUNT
} VulnCategory;

static const char *CATEGORY_NAMES[CAT_COUNT] = {
    "Dangerous C Function",
    "Format String",
    "Memory Function",
    "System Call"
};

typedef struct {
    const char   *name;       // 함수 이름
    VulnCategory  category;
    int           severity;   // 1=Low, 2=Medium, 3=High, 4=Critical
    const char   *reason;     // 위험 이유
} VulnFuncEntry;

static const VulnFuncEntry VULN_DB[] = {
    /* 위험 C 함수 */
    { "gets",          CAT_DANGEROUS, 4, "No bounds checking - always causes buffer overflow" },
    { "strcpy",        CAT_DANGEROUS, 3, "No bounds checking on destination buffer" },
    { "strcat",        CAT_DANGEROUS, 3, "No bounds checking on destination buffer" },
    { "sprintf",       CAT_DANGEROUS, 3, "No bounds checking on destination buffer" },
    { "vsprintf",      CAT_DANGEROUS, 3, "No bounds checking on destination buffer" },
    { "scanf",         CAT_DANGEROUS, 3, "No bounds checking with %%s specifier" },
    { "sscanf",        CAT_DANGEROUS, 2, "Potential buffer overflow with %%s" },
    { "strtok",        CAT_DANGEROUS, 1, "Not thread-safe, uses static buffer" },
    { "mktemp",        CAT_DANGEROUS, 2, "Race condition in temp file creation" },
    { "tmpnam",        CAT_DANGEROUS, 2, "Race condition in temp file creation" },

    /* 포맷 스트링 관련 */
    { "printf",        CAT_FORMAT,    2, "Format string vulnerability if user-controlled" },
    { "fprintf",       CAT_FORMAT,    2, "Format string vulnerability if user-controlled" },
    { "vprintf",       CAT_FORMAT,    2, "Format string vulnerability if user-controlled" },
    { "vfprintf",      CAT_FORMAT,    2, "Format string vulnerability if user-controlled" },
    { "syslog",        CAT_FORMAT,    2, "Format string vulnerability if user-controlled" },
    { "err",           CAT_FORMAT,    1, "Format string vulnerability if user-controlled" },
    { "warn",          CAT_FORMAT,    1, "Format string vulnerability if user-controlled" },

    /* 메모리 관련 */
    { "malloc",        CAT_MEMORY,    1, "Check for NULL return; heap overflow risk" },
    { "calloc",        CAT_MEMORY,    1, "Integer overflow in size calculation" },
    { "realloc",       CAT_MEMORY,    2, "UAF risk if old pointer reused after failure" },
    { "free",          CAT_MEMORY,    2, "Double-free or UAF if mismanaged" },
    { "alloca",        CAT_MEMORY,    3, "Stack allocation - stack overflow if size is large" },
    { "memcpy",        CAT_MEMORY,    2, "No overlap check; size must be validated" },
    { "memmove",       CAT_MEMORY,    1, "Size must be validated" },
    { "memset",        CAT_MEMORY,    1, "Size must be validated" },
    { "bcopy",         CAT_MEMORY,    2, "Deprecated; no bounds check" },

    /* 시스템 호출 */
    { "system",        CAT_SYSCALL,   4, "Command injection if input is user-controlled" },
    { "popen",         CAT_SYSCALL,   4, "Command injection if input is user-controlled" },
    { "execl",         CAT_SYSCALL,   3, "Argument injection risk" },
    { "execle",        CAT_SYSCALL,   3, "Argument injection risk" },
    { "execlp",        CAT_SYSCALL,   3, "PATH hijacking risk" },
    { "execv",         CAT_SYSCALL,   3, "Argument injection risk" },
    { "execve",        CAT_SYSCALL,   3, "Argument injection risk" },
    { "execvp",        CAT_SYSCALL,   3, "PATH hijacking risk" },
    { "execvpe",       CAT_SYSCALL,   3, "PATH hijacking risk" },
    { "putenv",        CAT_SYSCALL,   2, "Environment variable injection" },
    { "setenv",        CAT_SYSCALL,   2, "Environment variable injection" },
};

#define VULN_DB_SIZE ((int)(sizeof(VULN_DB) / sizeof(VULN_DB[0])))

/* ============================================================
 * 탐색 결과 구조체
 * ============================================================ */

typedef struct VulnMatch {
    const VulnFuncEntry *entry;   // 매칭된 취약 함수 정보
    uint64_t             addr;    // PLT/심볼 주소
    struct VulnMatch    *next;
} VulnMatch;

typedef struct {
    VulnMatch *head;
    int        count;
    int        count_by_cat[CAT_COUNT];
    int        count_by_sev[5];   // severity 1~4
} ScanResult;

/* ============================================================
 * ELF 파서 컨텍스트
 * ============================================================ */

typedef struct {
    uint8_t  *base;       // mmap 된 파일 시작
    size_t    size;       // 파일 크기
    int       is64;       // 1: ELF64, 0: ELF32

    /* 64비트 포인터로 통일 (32비트는 캐스트) */
    char     *dynstr;     // .dynstr 섹션
    size_t    dynstr_sz;

    /* 동적 심볼 테이블 */
    uint8_t  *dynsym;
    size_t    dynsym_entsz;
    size_t    dynsym_cnt;
} ElfCtx;

/* ============================================================
 * 유틸리티
 * ============================================================ */

static const VulnFuncEntry *lookup_vuln(const char *name) {
    for (int i = 0; i < VULN_DB_SIZE; i++) {
        if (strcmp(VULN_DB[i].name, name) == 0)
            return &VULN_DB[i];
    }
    return NULL;
}

static void result_add(ScanResult *res, const VulnFuncEntry *entry, uint64_t addr) {
    VulnMatch *m = malloc(sizeof(*m));
    if (!m) return;
    m->entry = entry;
    m->addr  = addr;
    m->next  = res->head;
    res->head = m;
    res->count++;
    res->count_by_cat[entry->category]++;
    if (entry->severity >= 1 && entry->severity <= 4)
        res->count_by_sev[entry->severity]++;
}

static void result_free(ScanResult *res) {
    VulnMatch *cur = res->head;
    while (cur) {
        VulnMatch *next = cur->next;
        free(cur);
        cur = next;
    }
    res->head = NULL;
}

/* ============================================================
 * ELF 파싱 및 탐색 (64비트)
 * ============================================================ */

static int parse_elf64(ElfCtx *ctx) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->base;

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) return 0;

    Elf64_Shdr *shdrs = (Elf64_Shdr *)(ctx->base + ehdr->e_shoff);
    Elf64_Shdr *shstrtab_hdr = &shdrs[ehdr->e_shstrndx];
    char *shstrtab = (char *)(ctx->base + shstrtab_hdr->sh_offset);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *sname = shstrtab + shdrs[i].sh_name;

        if (strcmp(sname, ".dynstr") == 0) {
            ctx->dynstr    = (char *)(ctx->base + shdrs[i].sh_offset);
            ctx->dynstr_sz = shdrs[i].sh_size;
        }
        if (strcmp(sname, ".dynsym") == 0) {
            ctx->dynsym       = ctx->base + shdrs[i].sh_offset;
            ctx->dynsym_entsz = shdrs[i].sh_entsize ? shdrs[i].sh_entsize : sizeof(Elf64_Sym);
            ctx->dynsym_cnt   = shdrs[i].sh_size / ctx->dynsym_entsz;
        }
    }
    return (ctx->dynstr && ctx->dynsym) ? 1 : 0;
}

static int parse_elf32(ElfCtx *ctx) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ctx->base;

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) return 0;

    Elf32_Shdr *shdrs = (Elf32_Shdr *)(ctx->base + ehdr->e_shoff);
    Elf32_Shdr *shstrtab_hdr = &shdrs[ehdr->e_shstrndx];
    char *shstrtab = (char *)(ctx->base + shstrtab_hdr->sh_offset);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *sname = shstrtab + shdrs[i].sh_name;

        if (strcmp(sname, ".dynstr") == 0) {
            ctx->dynstr    = (char *)(ctx->base + shdrs[i].sh_offset);
            ctx->dynstr_sz = shdrs[i].sh_size;
        }
        if (strcmp(sname, ".dynsym") == 0) {
            ctx->dynsym       = ctx->base + shdrs[i].sh_offset;
            ctx->dynsym_entsz = shdrs[i].sh_entsize ? shdrs[i].sh_entsize : sizeof(Elf32_Sym);
            ctx->dynsym_cnt   = shdrs[i].sh_size / ctx->dynsym_entsz;
        }
    }
    return (ctx->dynstr && ctx->dynsym) ? 1 : 0;
}

/* ============================================================
 * 메인 탐색 함수
 * ============================================================ */

/*
 * elf_scan_vuln_funcs()
 *
 * ELF 바이너리 경로를 받아 .dynsym 을 순회하며
 * VULN_DB 에 등록된 취약 함수를 탐색하고 ScanResult 를 채운다.
 *
 * 반환값: 0 성공, 음수 오류
 */
int elf_scan_vuln_funcs(const char *path, ScanResult *out_result) {
    if (!path || !out_result) return -1;
    memset(out_result, 0, sizeof(*out_result));

    /* 파일 열기 및 크기 확인 */
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return -2; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -3; }
    if (st.st_size < (off_t)EI_NIDENT) {
        fprintf(stderr, "File too small\n"); close(fd); return -4;
    }

    /* mmap */
    uint8_t *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror("mmap"); return -5; }

    /* ELF 매직 확인 */
    if (memcmp(base, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        munmap(base, st.st_size);
        return -6;
    }

    ElfCtx ctx = { .base = base, .size = st.st_size };
    ctx.is64 = (base[EI_CLASS] == ELFCLASS64);

    int ok = ctx.is64 ? parse_elf64(&ctx) : parse_elf32(&ctx);
    if (!ok) {
        fprintf(stderr, "Failed to locate .dynsym / .dynstr sections\n");
        munmap(base, st.st_size);
        return -7;
    }

    /* .dynsym 순회 */
    for (size_t i = 0; i < ctx.dynsym_cnt; i++) {
        uint64_t sym_value = 0;
        uint32_t name_idx  = 0;

        if (ctx.is64) {
            Elf64_Sym *sym = (Elf64_Sym *)(ctx.dynsym + i * ctx.dynsym_entsz);
            name_idx  = sym->st_name;
            sym_value = sym->st_value;
        } else {
            Elf32_Sym *sym = (Elf32_Sym *)(ctx.dynsym + i * ctx.dynsym_entsz);
            name_idx  = sym->st_name;
            sym_value = sym->st_value;
        }

        if (name_idx >= ctx.dynstr_sz) continue;
        const char *sym_name = ctx.dynstr + name_idx;
        if (*sym_name == '\0') continue;

        /* VULN_DB 조회 */
        const VulnFuncEntry *entry = lookup_vuln(sym_name);
        if (entry) {
            result_add(out_result, entry, sym_value);
        }
    }

    munmap(base, st.st_size);
    return 0;
}

/* ============================================================
 * 간단한 CLI 테스트 (출력부는 별도 구현 예정)
 * ============================================================ */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf_binary>\n", argv[0]);
        return 1;
    }

    ScanResult result;
    int ret = elf_scan_vuln_funcs(argv[1], &result);
    if (ret < 0) {
        fprintf(stderr, "Scan failed (code %d)\n", ret);
        return 1;
    }

    /* 임시 출력 (출력 함수 연동 전 확인용) */
    printf("[*] Found %d vulnerable function(s) in: %s\n\n", result.count, argv[1]);

    VulnMatch *m = result.head;
    while (m) {
        printf("  [SEV:%d] %-14s | %-20s | 0x%016llx | %s\n",
               m->entry->severity,
               CATEGORY_NAMES[m->entry->category],
               m->entry->name,
               (unsigned long long)m->addr,
               m->entry->reason);
        m = m->next;
    }

    result_free(&result);
    return 0;
}
