#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "common.h"

# include <elf.h> //add
# include <stddef.h> //add

elf_t *parse_elf(const char *filename);
void elf_free(elf_t *elf);
int     is_elf(elf_t *elf); //add
#endif// initial
