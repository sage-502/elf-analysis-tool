#include "elf_parser.h"
#include <stdlib.h>
#include <string.h>

elf_t *parse_elf(const char *filename)
{
    (void)filename;

    elf_t *elf = malloc(sizeof(elf_t));
    memset(elf, 0, sizeof(elf_t));

    /* ELF Header */
    elf->ehdr.e_type = ET_DYN; // PIE enabled

    /* Program Header 2개 */
    elf->phnum = 2;
    elf->phdrs = malloc(sizeof(Elf64_Phdr) * elf->phnum);

    /* NX enabled */
    elf->phdrs[0].p_type = PT_GNU_STACK;
    elf->phdrs[0].p_flags = PF_R | PF_W;

    /* RELRO 존재 */
    elf->phdrs[1].p_type = PT_GNU_RELRO;

    /* data */
    elf->size = 0x100;
    elf->data = malloc(elf->size);
    memset(elf->data, 0, elf->size);

    return elf;
}
void elf_free(elf_t *elf)
{
    if (!elf)
        return;

    if (elf->phdrs)
        free(elf->phdrs);

    if (elf->shdrs)
        free(elf->shdrs);

    if (elf->data)
        free(elf->data);

    if (elf->shstrtab)
        free(elf->shstrtab);

    free(elf);
}
