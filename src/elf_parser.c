#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "elf_parser.h"


/*
This code gets a file route as a its input, and it returns elf_t struct.
No matter what reason, if it fails, it prints an error message and kill the process. 
*/


/* 
file I/O
- open_elf : open ELF file and return file descriptor.
- get_file_size : return total size of ELF file.
- read_file : read file and store raw data into elf->data.
*/

int open_elf(const char *filename)
{
	int fd = open(filename, O_RDONLY);
   
    if(fd < 0)
    {
     	perror("open");
		exit(1);
	}

    return fd;
}


size_t get_file_size(int fd)
{
    off_t size = lseek(fd, 0, SEEK_END);

    if(size < 0)
    {
        perror("lseek");
        exit(1);
    }

    lseek(fd, 0, SEEK_SET);

    return (size_t) size;    
}


int read_file(int fd, elf_t *elf){
    ssize_t n;

    elf->size = get_file_size(fd);
    
    elf->data = malloc(elf->size);
    if (!elf->data)
    {
        perror("molloc");
        exit(1);
    }

    n = read(fd, elf->data, elf->size);
    if (n < 0)
    {
        perror("read");
        exit(1);
    }
    
    if (n != (ssize_t)elf->size)
    {
        fprintf(stderr, "read: incomplete read\n");
        exit(1);
    }

    return 0;
}


/* 
malloc and initialize elf struct
*/

elf_t *init_elf()
{
    elf_t *elf;

    elf = malloc(sizeof(elf_t));
    if (!elf)
    {
        perror("malloc");
        exit(1);
    }

    memset(elf, 0, sizeof(elf_t));

    return elf;
}


/*
free elf struct
*/

void free_elf(elf_t *elf)
{
    if (!elf)
        return;

    if (elf->data)
        free(elf->data);

    free(elf);
}


/*
parse ELF structure
*/

void parse_ehdr(elf_t *elf)
{
    elf->ehdr = *(Elf64_Ehdr *)elf->data;
    
    if (memcmp(elf->ehdr.e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "Not an ELF file\n");
        exit(1);
    }
}


void parse_phdr(elf_t *elf)
{
    elf->phnum = elf->ehdr.e_phnum;
    elf->phdrs = (Elf64_Phdr *)(elf->data + elf->ehdr.e_phoff);
}


void parse_shdr(elf_t *elf)
{
    elf->shnum = elf->ehdr.e_shnum;
    elf->shdrs = (Elf64_Shdr *)(elf->data + elf->ehdr.e_shoff);

    if (elf->ehdr.e_shstrndx != SHN_UNDEF)
    {
        Elf64_Shdr shstr = elf->shdrs[elf->ehdr.e_shstrndx];
        elf->shstrtab = (char *)(elf->data + shstr.sh_offset);
    }
}


/*
controller
*/

elf_t *parse_elf(const char *filename)
{
    int fd = open_elf(filename);
    elf_t *elf = init_elf();

    read_file(fd, elf);
    parse_ehdr(elf);
    parse_phdr(elf);
    parse_shdr(elf);

    close(fd);

    return elf;
}
void elf_free(elf_t *elf)
{
    if (!elf)
        return;

    if (elf->data)
        free(elf->data);

    // ❌ 얘네는 free 하면 안됨
    // free(elf->phdrs);
    // free(elf->shdrs);
    // free(elf->shstrtab);

    free(elf);
}
