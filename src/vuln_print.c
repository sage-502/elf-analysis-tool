#include <stdio.h>
#include "vuln.h"

void print_vuln(vuln_t v)
{
    int i;

    printf("===== Vulnerability Scan Result =====\n");
    printf("has_gets        : %d\n", v.has_gets);
    printf("has_strcpy      : %d\n", v.has_strcpy);
    printf("has_rwx_segment : %d\n", v.has_rwx_segment);
    printf("message count   : %d\n", v.count);

    for (i = 0; i < v.count; i++)
    {
        if (v.messages[i])
            printf("[%d] %s\n", i + 1, v.messages[i]);
    }
}
