#include <stdio.h>
#include <string.h>
#include <elf.h>
#include "vuln.h"
#include "elf_parser.h"

typedef struct s_danger_func
{
    const char *name;
    const char *category;
    const char *severity;
} danger_func_t;

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

static void add_hit(vuln_t *result, const danger_func_t *danger)
{
    int idx;

    if (!result || !danger || result->count >= 128)
        return;

    idx = result->count;

    strncpy(result->hits[idx].name, danger->name, sizeof(result->hits[idx].name) - 1);
    strncpy(result->hits[idx].category, danger->category, sizeof(result->hits[idx].category) - 1);
    strncpy(result->hits[idx].severity, danger->severity, sizeof(result->hits[idx].severity) - 1);

    result->hits[idx].name[sizeof(result->hits[idx].name) - 1] = '\0';
    result->hits[idx].category[sizeof(result->hits[idx].category) - 1] = '\0';
    result->hits[idx].severity[sizeof(result->hits[idx].severity) - 1] = '\0';

    result->count++;
}

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
            add_hit(result, danger);
    }
}

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

void print_vuln(vuln_t v)
{
    int i;

    printf("===== Vulnerability Scan Result =====\n");
    printf("count: %d\n", v.count);

    for (i = 0; i < v.count; i++)
    {
        printf("[%d] name=%s | category=%s | severity=%s\n",
               i + 1,
               v.hits[i].name,
               v.hits[i].category,
               v.hits[i].severity);
    }
}
