#ifndef VULN_H
#define VULN_H

#include "elf_parser.h"

#define MAX_VULN 32

typedef struct s_vuln
{
    int has_gets;
    int has_strcpy;
    int has_rwx_segment;

    int count;
    char *messages[MAX_VULN];
} vuln_t;

vuln_t analyze_vulnerability(elf_t *elf);
void print_vuln(vuln_t v);
void free_vuln(vuln_t *v);

#endif

