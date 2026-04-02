#ifndef MITIGATION_H
#define MITIGATION_H

#include "common.h"

typedef struct s_mitigation
{
    int nx;
    int pie;
    int relro;
    int canary;

} mitigation_t;

mitigation_t analyze_mitigation(elf_t *elf);

#endif
