#ifndef VULN_H
#define VULN_H

#include "common.h"
#include "mitigation.h" 
typedef struct s_vuln
{
    int dummy; // 나중에 확장
} vuln_t;

vuln_t analyze_vulnerability(elf_t *elf);
void print_result(mitigation_t m, vuln_t v);
#endif
