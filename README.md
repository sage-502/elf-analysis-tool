## Vulnerable Function Detection

This module detects usage of unsafe functions such as:

- gets
- strcpy
- sprintf
- scanf

It analyzes ELF symbol tables (.symtab, .dynsym) and filters function symbols.
Duplicate results are removed for clarity.
