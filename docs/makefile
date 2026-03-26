CC = gcc
CFLAGS = -Wall -Wextra -g

SRC = main.c \
      parser/elf_load.c \
      parser/elf_parse_ehdr.c \
      parser/elf_parse_phdr.c \
      parser/elf_parse_shdr.c \
      parser/elf_parse_shstrtab.c \
      analysis/vuln.c

OBJ = $(SRC:.c=.o)

TARGET = elfsec

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ)

clean:
	rm -f $(OBJ) $(TARGET)
