#include "mitigation.h"
#include <string.h>

/* ========================= */
/* NX 검사 */
/* ========================= */
static int check_nx(elf_t *elf)
{
    if (!elf || !elf->phdrs)
        return 0;

    for (int i = 0; i < elf->phnum; i++)
    {
        if (elf->phdrs[i].p_type == PT_GNU_STACK)
        {
            if (elf->phdrs[i].p_flags & PF_X)
                return 0; // NX disabled
            else
                return 1; // NX enabled
        }
    }

    // PT_GNU_STACK 없으면 기본적으로 enabled
    return 1;
}

/* ========================= */
/* PIE 검사 */
/* ========================= */
static int check_pie(elf_t *elf)
{
    if (!elf)
        return 0;

    if (elf->ehdr.e_type == ET_DYN)
        return 1;
    else
        return 0;
}

/* ========================= */
/* RELRO 검사 */
/* ========================= */
static int check_relro(elf_t *elf)
{
    if (!elf || !elf->phdrs || !elf->data)
        return 0;

    int has_relro = 0;
    int bind_now = 0;

    Elf64_Dyn *dyn = NULL;
    size_t dyn_size = 0;

    for (int i = 0; i < elf->phnum; i++)
    {
        /* RELRO 존재 여부 */
        if (elf->phdrs[i].p_type == PT_GNU_RELRO)
            has_relro = 1;

        /* dynamic section 찾기 */
        if (elf->phdrs[i].p_type == PT_DYNAMIC)
        {
            if (elf->phdrs[i].p_offset + elf->phdrs[i].p_filesz > elf->size)
                continue;

            dyn = (Elf64_Dyn *)(elf->data + elf->phdrs[i].p_offset);
            dyn_size = elf->phdrs[i].p_filesz;
        }
    }

    /* RELRO 자체 없음 */
    if (!has_relro)
        return 0;

    /* dynamic 없으면 partial로 간주 */
    if (!dyn)
        return 1;

    /* BIND_NOW 검사 */
    size_t max = dyn_size / sizeof(Elf64_Dyn);

    for (size_t i = 0; i < max; i++)
    {
        if (dyn[i].d_tag == DT_NULL)
            break;

        if (dyn[i].d_tag == DT_BIND_NOW)
        {
            bind_now = 1;
            break;
        }
    }

    if (bind_now)
        return 2; // FULL RELRO
    else
        return 1; // PARTIAL RELRO
}

/* ========================= */
/* Canary 검사 */
/* ========================= */
static int check_canary(elf_t *elf)
{
    if (!elf || !elf->shdrs || !elf->data)
        return 0;

    for (int i = 0; i < elf->shnum; i++)
    {
        Elf64_Shdr sh = elf->shdrs[i];

        if (sh.sh_type == SHT_DYNSYM || sh.sh_type == SHT_SYMTAB)
        {
            /* 경계 체크 */
            if (sh.sh_offset + sh.sh_size > elf->size)
                continue;

            if (sh.sh_entsize == 0)
                continue;

            int count = sh.sh_size / sh.sh_entsize;

            /* string table index 체크 */
            if (sh.sh_link >= elf->shnum)
                continue;

            Elf64_Shdr str_sh = elf->shdrs[sh.sh_link];

            if (str_sh.sh_offset + str_sh.sh_size > elf->size)
                continue;

            char *strtab = (char *)(elf->data + str_sh.sh_offset);
            Elf64_Sym *sym = (Elf64_Sym *)(elf->data + sh.sh_offset);

            for (int j = 0; j < count; j++)
            {
                if (sym[j].st_name >= str_sh.sh_size)
                    continue;

                char *name = strtab + sym[j].st_name;

                if (strcmp(name, "__stack_chk_fail") == 0)
                    return 1;
            }
        }
    }

    return 0;
}

/* ========================= */
/* 전체 mitigation 분석 */
/* ========================= */
mitigation_t analyze_mitigation(elf_t *elf)
{
    mitigation_t m;

    /* 기본값 (안전) */
    m.nx = 0;
    m.pie = 0;
    m.relro = 0;
    m.canary = 0;

    if (!elf)
        return m;

    m.nx = check_nx(elf);
    m.pie = check_pie(elf);
    m.relro = check_relro(elf);
    m.canary = check_canary(elf);

    return m;
}
