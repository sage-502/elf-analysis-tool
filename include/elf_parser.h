#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "common.h"

elf_t *parse_elf(const char *filename);
void elf_free(elf_t *elf);
#endif// initial
