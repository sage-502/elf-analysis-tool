#ifndef ELF_PARSER_H
# define ELF_PARSER_H

# include <elf.h>
# include <stddef.h>

# include "common.h"


elf_t  *parse_elf(const char *filename); // parser API

void    free_elf(elf_t *elf); // free elf_t

int     is_elf(elf_t *elf); // check ELF (option)

#endif
