#include "vuln.h"
#include <stdio.h>
#include "mitigation.h"
vuln_t analyze_vulnerability(elf_t *elf)
{
    vuln_t v;
    v.dummy = 0;
    return v;
}

void print_result(mitigation_t m, vuln_t v)
{
    printf("NX: %s\n", m.nx ? "Enabled" : "Disabled");
    printf("PIE: %s\n", m.pie ? "Enabled" : "Disabled");

    if (m.relro == 0)
        printf("RELRO: No RELRO\n");
    else if (m.relro == 1)
        printf("RELRO: Partial RELRO\n");
    else
        printf("RELRO: Full RELRO\n");

    printf("Canary: %s\n", m.canary ? "Enabled" : "Disabled");
}
