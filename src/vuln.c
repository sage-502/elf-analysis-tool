#include <stdio.h>
#include <string.h>
#include <elf.h>
#include "vuln.h"
#include "elf_parser.h"

/*
 * 위험 함수 정보를 저장하는 구조체
 * - name: 함수 이름
 * - category: 어떤 유형의 위험인지
 * - severity: 위험도
 */
typedef struct s_danger_func
{
    const char *name;
    const char *category;
    const char *severity;
} danger_func_t;

/*
 * 위험 함수 목록 데이터베이스
 * ELF 안에서 읽은 심볼 이름이 이 목록과 일치하면
 * 취약 함수로 판단한다.
 */
static const danger_func_t g_danger_funcs[] = {
    {"gets",     "buffer overflow", "HIGH"},
    {"strcpy",   "buffer overflow", "HIGH"},
    {"strcat",   "buffer overflow", "HIGH"},
    {"sprintf",  "buffer overflow", "HIGH"},
    {"vsprintf", "buffer overflow", "HIGH"},
    {"scanf",    "input handling",  "MEDIUM"},
    {"fscanf",   "input handling",  "MEDIUM"},
    {"sscanf",   "input handling",  "MEDIUM"},
    {"memcpy",   "memory copy",     "MEDIUM"},
    {"read",     "raw input",       "MEDIUM"},
    {"recv",     "network input",   "MEDIUM"},
    {"system",   "command exec",    "HIGH"},
    {"popen",    "command exec",    "HIGH"},
    {NULL,       NULL,              NULL}
};

/*
 * 섹션 이름으로 Section Header를 찾는 함수
 * 예:
 *   ".dynsym", ".dynstr", ".symtab", ".strtab"
 */
static Elf64_Shdr *find_section_by_name(elf_t *elf, const char *name)
{
    int i;
    const char *secname;

    if (!elf || !name || !elf->shdrs || !elf->shstrtab)
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
 * 이름이 위험 함수 목록에 있는지 확인
 * 있으면 해당 danger_func_t 반환
 */
static const danger_func_t *find_danger_func(const char *name)
{
    int i;

    if (!name)
        return NULL;

    for (i = 0; g_danger_funcs[i].name != NULL; i++)
    {
        if (strcmp(g_danger_funcs[i].name, name) == 0)
            return &g_danger_funcs[i];
    }
    return NULL;
}

/*
 * 탐지된 위험 함수를 결과 구조체에 추가
 * table_name에는 어느 심볼 테이블에서 찾았는지도 같이 저장
 *
 * 중복 제거는 하지 않으므로
 * 같은 함수가 .dynsym, .symtab 둘 다 있으면 둘 다 저장됨
 */
static void add_hit(vuln_t *result, const danger_func_t *danger, const char *table_name)
{
    int idx;

    if (!result || !danger || !table_name || result->count >= 128)
        return;

    idx = result->count;

    strncpy(result->hits[idx].name, danger->name, sizeof(result->hits[idx].name) - 1);
    strncpy(result->hits[idx].category, danger->category, sizeof(result->hits[idx].category) - 1);
    strncpy(result->hits[idx].severity, danger->severity, sizeof(result->hits[idx].severity) - 1);
    strncpy(result->hits[idx].table_name, table_name, sizeof(result->hits[idx].table_name) - 1);

    result->hits[idx].name[sizeof(result->hits[idx].name) - 1] = '\0';
    result->hits[idx].category[sizeof(result->hits[idx].category) - 1] = '\0';
    result->hits[idx].severity[sizeof(result->hits[idx].severity) - 1] = '\0';
    result->hits[idx].table_name[sizeof(result->hits[idx].table_name) - 1] = '\0';

    result->count++;
}

/*
 * 하나의 심볼 테이블을 스캔하는 함수
 * symsec_name: 검사할 심볼 테이블 이름
 * strsec_name: 해당 문자열 테이블 이름
 *
 * 예:
 *   scan_symbol_table(elf, ".dynsym", ".dynstr", &result);
 *   scan_symbol_table(elf, ".symtab", ".strtab", &result);
 */
static void scan_symbol_table(elf_t *elf, const char *symsec_name, const char *strsec_name, vuln_t *result)
{
    Elf64_Shdr *sym_sh;
    Elf64_Shdr *str_sh;
    Elf64_Sym *symbols;
    const char *strtab;
    int sym_count;
    int i;

    sym_sh = find_section_by_name(elf, symsec_name);
    str_sh = find_section_by_name(elf, strsec_name);

    if (!sym_sh || !str_sh || sym_sh->sh_entsize == 0)
        return;

    symbols = (Elf64_Sym *)(elf->data + sym_sh->sh_offset);
    strtab = (const char *)(elf->data + str_sh->sh_offset);
    sym_count = (int)(sym_sh->sh_size / sym_sh->sh_entsize);

    for (i = 0; i < sym_count; i++)
    {
        const char *sym_name;
        const danger_func_t *danger;

        if (symbols[i].st_name == 0)
            continue;

        sym_name = strtab + symbols[i].st_name;
        if (!sym_name || sym_name[0] == '\0')
            continue;

        danger = find_danger_func(sym_name);
        if (danger)
            add_hit(result, danger, symsec_name);
    }
}

/*
 * 취약 함수 분석 메인 함수
 * - .dynsym / .dynstr 검사
 * - .symtab / .strtab 검사
 */
vuln_t analyze_vulnerability(elf_t *elf)
{
    vuln_t result;

    memset(&result, 0, sizeof(result));

    if (!elf)
        return result;

    scan_symbol_table(elf, ".dynsym", ".dynstr", &result);
    scan_symbol_table(elf, ".symtab", ".strtab", &result);

    return result;
}

/*
 * 분석 결과 출력
 * 어느 테이블에서 발견되었는지도 함께 출력
 */
void print_vuln(vuln_t v)
{
    int i;

    printf("===== Vulnerability Scan Result =====\n");
    printf("count: %d\n", v.count);

    for (i = 0; i < v.count; i++)
    {
        printf("[%d] name=%s | category=%s | severity=%s | found_in=%s\n",
               i + 1,
               v.hits[i].name,
               v.hits[i].category,
               v.hits[i].severity,
               v.hits[i].table_name);
    }
}
