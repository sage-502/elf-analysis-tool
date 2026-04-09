#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "elf_parser.h"

/*
** 테스트용 ELF 객체 생성
** - 실제 파일 파싱 없이 mitigation / vuln 로직 먼저 테스트할 때 사용
** - free_elf()로 해제 가능하게 전부 malloc 기반으로 맞춤
*/
elf_t *create_test_elf(void)
{
    elf_t *elf;

    elf = calloc(1, sizeof(elf_t));
    if (!elf)
        return (NULL);

    /* -------------------- */
    /* ELF Header 하드코딩  */
    /* -------------------- */
    elf->ehdr.e_ident[EI_MAG0] = ELFMAG0;
    elf->ehdr.e_ident[EI_MAG1] = ELFMAG1;
    elf->ehdr.e_ident[EI_MAG2] = ELFMAG2;
    elf->ehdr.e_ident[EI_MAG3] = ELFMAG3;
    elf->ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    elf->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    elf->ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    elf->ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;

    elf->ehdr.e_type = ET_DYN;               /* PIE 테스트용 */
    elf->ehdr.e_machine = EM_X86_64;
    elf->ehdr.e_version = EV_CURRENT;
    elf->ehdr.e_entry = 0x1050;
    elf->ehdr.e_phoff = sizeof(Elf64_Ehdr);
    elf->ehdr.e_shoff = 0x2000;
    elf->ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    elf->ehdr.e_phentsize = sizeof(Elf64_Phdr);
    elf->ehdr.e_shentsize = sizeof(Elf64_Shdr);

    /* -------------------- */
    /* Program Header       */
    /* -------------------- */
    elf->phnum = 4;
    elf->ehdr.e_phnum = elf->phnum;
    elf->phdrs = calloc(elf->phnum, sizeof(Elf64_Phdr));
    if (!elf->phdrs)
        return (free(elf), NULL);

    /* PHDR[0] : LOAD (R-X) */
    elf->phdrs[0].p_type = PT_LOAD;
    elf->phdrs[0].p_flags = PF_R | PF_X;

    /* PHDR[1] : LOAD (RW-) */
    elf->phdrs[1].p_type = PT_LOAD;
    elf->phdrs[1].p_flags = PF_R | PF_W;

    /* PHDR[2] : GNU_STACK (RW-, NX enabled) */
    elf->phdrs[2].p_type = PT_GNU_STACK;
    elf->phdrs[2].p_flags = PF_R | PF_W;

    /* PHDR[3] : GNU_RELRO */
    elf->phdrs[3].p_type = PT_GNU_RELRO;
    elf->phdrs[3].p_flags = PF_R;

    /* -------------------- */
    /* Section Header       */
    /* -------------------- */
    elf->shnum = 6;
    elf->ehdr.e_shnum = elf->shnum;
    elf->ehdr.e_shstrndx = 5;
    elf->shdrs = calloc(elf->shnum, sizeof(Elf64_Shdr));
    if (!elf->shdrs)
    {
        free(elf->phdrs);
        free(elf);
        return (NULL);
    }

    /*
    ** section index 예시
    ** 0: NULL
    ** 1: .text
    ** 2: .dynamic
    ** 3: .dynsym
    ** 4: .dynstr
    ** 5: .shstrtab
    */

    elf->shdrs[1].sh_name = 1;       /* ".text" */
    elf->shdrs[1].sh_type = SHT_PROGBITS;
    elf->shdrs[1].sh_flags = SHF_ALLOC | SHF_EXECINSTR;

    elf->shdrs[2].sh_name = 7;       /* ".dynamic" */
    elf->shdrs[2].sh_type = SHT_DYNAMIC;
    elf->shdrs[2].sh_flags = SHF_ALLOC | SHF_WRITE;
    elf->shdrs[2].sh_offset = 0x900;
    elf->shdrs[2].sh_size = 2 * sizeof(Elf64_Dyn);
    elf->shdrs[2].sh_entsize = sizeof(Elf64_Dyn);

    elf->shdrs[3].sh_name = 16;      /* ".dynsym" */
    elf->shdrs[3].sh_type = SHT_DYNSYM;
    elf->shdrs[3].sh_offset = 0xa00;
    elf->shdrs[3].sh_size = 2 * sizeof(Elf64_Sym);
    elf->shdrs[3].sh_entsize = sizeof(Elf64_Sym);
    elf->shdrs[3].sh_link = 4;       /* linked to .dynstr */

    elf->shdrs[4].sh_name = 24;      /* ".dynstr" */
    elf->shdrs[4].sh_type = SHT_STRTAB;
    elf->shdrs[4].sh_offset = 0xb00;
    elf->shdrs[4].sh_size = 64;

    elf->shdrs[5].sh_name = 32;      /* ".shstrtab" */
    elf->shdrs[5].sh_type = SHT_STRTAB;

    /* -------------------- */
    /* Section Name String Table */
    /* -------------------- */
    elf->shstrtab = calloc(1, 64);
    if (!elf->shstrtab)
    {
        free(elf->shdrs);
        free(elf->phdrs);
        free(elf);
        return (NULL);
    }
    strcpy(elf->shstrtab + 1, ".text");
    strcpy(elf->shstrtab + 7, ".dynamic");
    strcpy(elf->shstrtab + 16, ".dynsym");
    strcpy(elf->shstrtab + 24, ".dynstr");
    strcpy(elf->shstrtab + 32, ".shstrtab");

    /* -------------------- */
    /* raw data 더미 생성   */
    /* -------------------- */
    elf->size = 0x2000;
    elf->data = calloc(1, elf->size);
    if (!elf->data)
    {
        free(elf->shstrtab);
        free(elf->shdrs);
        free(elf->phdrs);
        free(elf);
        return (NULL);
    }

    /*
    ** .dynamic 영역에 DT_BIND_NOW 넣어서 Full RELRO처럼 보이게 세팅 가능
    ** offset 0x900 위치에 Elf64_Dyn 2개를 박음
    */
    {
        Elf64_Dyn *dyn = (Elf64_Dyn *)(elf->data + 0x900);

        dyn[0].d_tag = DT_BIND_NOW;
        dyn[0].d_un.d_val = 1;
        dyn[1].d_tag = DT_NULL;
        dyn[1].d_un.d_val = 0;
    }

    /*
    ** .dynstr 예시
    ** "__stack_chk_fail", "puts" 넣어 Canary / 심볼 탐지 테스트 가능
    */
    {
        char *dynstr = (char *)(elf->data + 0xb00);

        dynstr[0] = '\0';
        strcpy(dynstr + 1, "__stack_chk_fail");
        strcpy(dynstr + 20, "puts");
    }

    /*
    ** .dynsym 예시
    ** 심볼 2개 생성
    */
    {
        Elf64_Sym *sym = (Elf64_Sym *)(elf->data + 0xa00);

        /* 첫 번째는 보통 NULL symbol */
        sym[0].st_name = 0;
        sym[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);

        /* __stack_chk_fail */
        sym[1].st_name = 1; /* dynstr + 1 */
        sym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        sym[1].st_shndx = SHN_UNDEF;
    }

    return (elf);
}

int main(void)
{
    elf_t *elf;
    mitigation_t m;
    vuln_t v;

    elf = create_test_elf();
    if (!elf)
        return (1);

    m = analyze_mitigation(elf);
    v = analyze_vulnerability(elf);

    print_result(m, v);
    free_elf(elf);
    return (0);
}
