#include <stdio.h>
#include <string.h>
#include "vuln_scan.h"

/*
 * 위험 함수 데이터베이스
 * 중복 제거 없이, 발견될 때마다 그대로 출력한다.
 */
static const danger_func_t g_danger_funcs[] = {
    {"gets",     "buffer overflow", "HIGH",   "No bounds checking"},
    {"strcpy",   "buffer overflow", "HIGH",   "Copies without length check"},
    {"strcat",   "buffer overflow", "HIGH",   "Appends without bounds check"},
    {"sprintf",  "buffer overflow", "HIGH",   "Unbounded formatted write"},
    {"vsprintf", "buffer overflow", "HIGH",   "Unbounded formatted write"},
    {"scanf",    "input handling",  "MEDIUM", "May overflow depending on format"},
    {"fscanf",   "input handling",  "MEDIUM", "May overflow depending on format"},
    {"sscanf",   "input handling",  "MEDIUM", "May overflow depending on format"},
    {"memcpy",   "memory copy",     "MEDIUM", "Unsafe if size is unchecked"},
    {"read",     "raw input",       "MEDIUM", "Can overflow if length is misused"},
    {"recv",     "network input",   "MEDIUM", "Can overflow if length is misused"},
    {"system",   "command exec",    "HIGH",   "Executes shell command"},
    {"popen",    "command exec",    "HIGH",   "Executes shell command"},
    {NULL,       NULL,              NULL,     NULL}
};

/*
 * 섹션 이름으로 Section Header를 찾는다.
 * 예: ".dynsym", ".dynstr", ".symtab", ".strtab"
 */
Elf64_Shdr *find_section_by_name(elf_t *elf, const char *name)
{
    int i;
    const char *secname;

    if (elf == NULL || name == NULL || elf->shdrs == NULL || elf->shstrtab == NULL)
        return NULL;

    for (i = 0; i < elf->shnum; i++)
    {
        secname = elf->shstrtab + elf->shdrs[i].sh_name;
        if (strcmp(secname, name) == 0)
            return &elf->shdrs[i];
    }
    return NULL;
}

/*
 * 함수 이름이 위험 함수 목록에 있는지 확인한다.
 * 있으면 해당 danger_func_t를 반환, 없으면 NULL 반환
 */
const danger_func_t *find_danger_func(const char *name)
{
    int i;

    if (name == NULL)
        return NULL;

    for (i = 0; g_danger_funcs[i].name != NULL; i++)
    {
        if (strcmp(g_danger_funcs[i].name, name) == 0)
            return &g_danger_funcs[i];
    }
    return NULL;
}

/*
 * 심볼 테이블 하나를 스캔한다.
 * symsec_name: ".dynsym" 또는 ".symtab"
 * strsec_name: ".dynstr" 또는 ".strtab"
 *
 * 중복 제거를 하지 않으므로, 발견되는 대로 모두 출력한다.
 */
void scan_symbol_table(elf_t *elf, const char *symsec_name, const char *strsec_name)
{
    Elf64_Shdr *sym_sh;
    Elf64_Shdr *str_sh;
    Elf64_Sym  *symbols;
    const char *strtab;
    int sym_count;
    int i;

    if (elf == NULL || symsec_name == NULL || strsec_name == NULL)
        return;

    sym_sh = find_section_by_name(elf, symsec_name);
    str_sh = find_section_by_name(elf, strsec_name);

    if (sym_sh == NULL || str_sh == NULL)
    {
        printf("[-] section not found: %s or %s\n", symsec_name, strsec_name);
        return;
    }

    if (sym_sh->sh_entsize == 0)
    {
        printf("[-] invalid symbol entry size in %s\n", symsec_name);
        return;
    }

    /* raw data에서 실제 심볼 배열과 문자열 테이블 위치 계산 */
    symbols = (Elf64_Sym *)(elf->data + sym_sh->sh_offset);
    strtab  = (const char *)(elf->data + str_sh->sh_offset);
    sym_count = (int)(sym_sh->sh_size / sym_sh->sh_entsize);

    printf("\n[*] Scanning %s using %s ...\n", symsec_name, strsec_name);
    printf("    total symbols: %d\n", sym_count);

    for (i = 0; i < sym_count; i++)
    {
        const char *sym_name;
        const danger_func_t *danger;

        /* 이름 없는 심볼은 건너뜀 */
        if (symbols[i].st_name == 0)
            continue;

        sym_name = strtab + symbols[i].st_name;
        if (sym_name == NULL || sym_name[0] == '\0')
            continue;

        danger = find_danger_func(sym_name);
        if (danger != NULL)
        {
            printf("[FOUND] table=%-8s name=%-10s type=%-15s severity=%-6s desc=%s\n",
                   symsec_name,
                   danger->name,
                   danger->category,
                   danger->severity,
                   danger->description);
        }
    }
}

/*
 * 전체 위험 함수 탐색
 * 1) .dynsym / .dynstr
 * 2) .symtab / .strtab
 *
 * 중복 제거 없이 둘 다 스캔해서 전부 출력
 */
void scan_dangerous_functions(elf_t *elf)
{
    if (elf == NULL)
    {
        printf("[-] elf is NULL\n");
        return;
    }

    printf("========================================\n");
    printf(" Dangerous Function Scan Start\n");
    printf("========================================\n");

    scan_symbol_table(elf, ".dynsym", ".dynstr");
    scan_symbol_table(elf, ".symtab", ".strtab");

    printf("\n========================================\n");
    printf(" Dangerous Function Scan End\n");
    printf("========================================\n");
}
