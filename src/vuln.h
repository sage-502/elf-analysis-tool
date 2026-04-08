#ifndef VULN_H
#define VULN_H

#include "elf_parser.h"

typedef struct s_vuln_hit
{
    char name[64];
    char category[64];
    char severity[16];
    char table_name[32];
} vuln_hit_t;

typedef struct s_vuln
{
    int count;
    vuln_hit_t hits[128];
} vuln_t;

vuln_t analyze_vulnerability(elf_t *elf);
void print_vuln(vuln_t v);

#endif
