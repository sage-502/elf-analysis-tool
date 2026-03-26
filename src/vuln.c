#include <stdio.h>
#include <string.h>
#include <elf.h>
#include "vuln.h"

/*
 * 탐지할 위험 함수 목록
 * (버퍼 오버플로우 등 취약점 유발 가능)
 */
static char *dangerous_funcs[] = {
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "scanf",
    "sscanf",
    "fscanf",
    NULL
};

/*
 * 특정 symbol table(.symtab 또는 .dynsym)을 분석하여
 * 취약 함수가 포함되어 있는지 확인하는 함수
 */
static void analyze_symtab(elf_t *elf, Elf64_Shdr *shdr)
{
    Elf64_Sym *symtab;   // symbol table 시작 주소
    char *strtab;        // string table (함수 이름 저장)
    int count;           // symbol 개수

    /* symbol table 위치 계산 */
    symtab = (Elf64_Sym *)(elf->data + shdr->sh_offset);

    /* symbol 개수 계산 */
    count = shdr->sh_size / sizeof(Elf64_Sym);

    /* 해당 symbol table과 연결된 string table 가져오기 */
    Elf64_Shdr str_shdr = elf->shdrs[shdr->sh_link];
    strtab = (char *)(elf->data + str_shdr.sh_offset);

    /* 모든 symbol 순회 */
    for (int i = 0; i < count; i++) {
        Elf64_Sym sym = symtab[i];

        /* 함수 타입(symbol type == STT_FUNC)만 분석 */
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC)
            continue;

        /* 함수 이름 가져오기 */
        char *name = strtab + sym.st_name;

        /* 유효하지 않은 이름은 건너뜀 */
        if (!name || name[0] == '\0')
            continue;

        /* 위험 함수 목록과 비교 */
        for (int j = 0; dangerous_funcs[j]; j++) {
            if (strcmp(name, dangerous_funcs[j]) == 0) {
                printf("[!] Vulnerable function detected: %s\n", name);
            }
        }
    }
}

/*
 * ELF 전체에서 취약 함수 탐지를 수행하는 메인 함수
 */
void analyze_vuln(elf_t *elf)
{
    printf("[*] Scanning for vulnerable functions...\n");

    int has_symtab = 0;

    /* 모든 section header 순회 */
    for (int i = 0; i < elf->shnum; i++) {
        char *secname = elf->shstrtab + elf->shdrs[i].sh_name;

        /*
         * symbol table section 탐색
         * - .symtab : 정적 심볼 테이블
         * - .dynsym : 동적 심볼 테이블
         */
        if (strcmp(secname, ".symtab") == 0 ||
            strcmp(secname, ".dynsym") == 0) {

            analyze_symtab(elf, &elf->shdrs[i]);
            has_symtab = 1;
        }
    }

    /* symbol table이 없는 경우 */
    if (!has_symtab) {
        printf("[-] No symbol table found\n");
    }
}
