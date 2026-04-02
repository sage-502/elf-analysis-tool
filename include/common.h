#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

typedef struct s_elf
{
    Elf64_Ehdr ehdr;

    Elf64_Phdr *phdrs;
    int phnum;

    Elf64_Shdr *shdrs;
    int shnum;

    char *shstrtab;

    unsigned char *data;
    size_t size;

} elf_t;

#endif
