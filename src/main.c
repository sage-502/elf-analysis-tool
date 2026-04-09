# include <stdio.h>

# include "common.h"
# include "elf_parser.h"
# include "mitigation.h"
# include "vuln.h"


int main(int argc, char **argv)
{
    elf_t *elf = parse_elf(argv[1]);

    mitigation_t m = analyze_mitigation(elf);

    vuln_t v = analyze_vulnerability(elf);

    print_vuln(v);

    free_elf(elf);

    return 0;
}
