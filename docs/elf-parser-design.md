# 📄 ELF Parser 설계 문서

## 1. 개요

본 모듈은 ELF(Executable and Linkable Format) 파일을 입력받아, </br>
파일의 구조를 파싱하고 이를 구조체 형태로 반환하는 역할을 수행한다.

이 파서는 이후 모듈(보호기법 분석, 취약점 탐지 등)의 기반 데이터로 사용된다.

프로젝트 목표:
사용자가 입력한 바이너리를 분석하여 구조 및 보안 정보를 제공 

---

## 2. 역할 및 책임

ELF Parser의 주요 역할은 다음과 같다:

* ELF 파일을 메모리에 로드
* ELF Header 파싱
* Program Header Table 파싱
* Section Header Table 파싱
* Section Name String Table 연결
* 파싱 결과를 구조체(`elf_t`)에 저장

Parser는 해석이 아니라 **데이터 제공 역할만 수행**

---

## 3. 데이터 구조 설계

```c
typedef struct s_elf
{
    /* 기본 헤더 */
    Elf64_Ehdr ehdr;

    /* Program Header */
    Elf64_Phdr *phdrs;
    int phnum;

    /* Section Header */
    Elf64_Shdr *shdrs;
    int shnum;

    /* Section name string table */
    char *shstrtab;

    /* 파일 raw 데이터 */
    unsigned char *data;
    size_t size;

} elf_t;
```

### 설계 의도

* `data`: ELF 전체를 메모리에 로드하여 offset 기반 접근 가능하도록 함
* `ehdr`: ELF 전체 구조의 기준 정보 제공
* `phdrs`: segment 기반 분석 (NX, PIE 등)
* `shdrs`: section 기반 분석 (symbol, relocation 등)
* `shstrtab`: section 이름 해석에 사용

---

## 4. 전체 처리 흐름

```text
[파일 입력]
    ↓
[파일 전체 메모리 로드]
    ↓
[ELF Header 파싱]
    ↓
[Program Header 파싱]
    ↓
[Section Header 파싱]
    ↓
[shstrtab 연결]
    ↓
[elf_t 반환]
```

---

## 5. 상세 설계

### 5.1 파일 로딩

#### 목적

파일 전체를 메모리에 로드하여 ELF의 offset 기반 구조를 처리하기 위함

#### 함수

```c
int elf_load_file(const char *path, elf_t *elf);
```

#### 처리 과정

* 파일 open
* 파일 크기 확인 (fstat)
* 메모리 할당
* 전체 파일 read

---

### 5.2 ELF Header 파싱

#### 함수

```c
int elf_parse_ehdr(elf_t *elf);
```

#### 처리

* `data`의 시작 부분에서 `Elf64_Ehdr` 복사
* ELF 유효성 검사 수행

#### 검증 항목

* Magic Number (`0x7f 'ELF'`)
* 64bit 여부 (`EI_CLASS`)
* Endianness

---

### 5.3 Program Header 파싱

#### 함수

```c
int elf_parse_phdrs(elf_t *elf);
```

#### 처리

* 위치: `ehdr.e_phoff`
* 개수: `ehdr.e_phnum`

```c
phdrs[i] = *(Elf64_Phdr *)(data + offset);
```

#### 활용

* NX 여부 확인 (PT_GNU_STACK)
* PIE 여부 판단
* 메모리 segment 분석

---

### 5.4 Section Header 파싱

#### 함수

```c
int elf_parse_shdrs(elf_t *elf);
```

#### 처리

* 위치: `ehdr.e_shoff`
* 개수: `ehdr.e_shnum`

---

### 5.5 Section Name String Table 연결

#### 함수

```c
int elf_parse_shstrtab(elf_t *elf);
```

#### 처리

* index: `ehdr.e_shstrndx`
* 해당 section의 offset 사용

```c
elf->shstrtab = data + shdrs[index].sh_offset;
```

#### 활용

```c
section_name = shstrtab + shdr.sh_name;
```

---

## 6. 함수 구조 설계

```c
int elf_parse(const char *path, elf_t *elf)
{
    elf_load_file(path, elf);

    elf_parse_ehdr(elf);
    elf_parse_phdrs(elf);
    elf_parse_shdrs(elf);
    elf_parse_shstrtab(elf);

    return 0;
}
```

---

## 7. 메모리 관리

#### 해제 함수

```c
void elf_free(elf_t *elf);
```

#### 처리

* phdrs 해제
* shdrs 해제
* data 해제

---

## 8. 예외 처리 및 안정성

### 8.1 범위 검사

```c
offset + size <= elf->size
```

모든 접근 전에 반드시 검사

---

### 8.2 오류 처리

* malloc 실패 체크
* 파일 read 실패 처리
* ELF 형식이 아닐 경우 종료

---

## 9. 모듈 구조

```text
parser/
 ├── elf_load.c
 ├── elf_parse_ehdr.c
 ├── elf_parse_phdr.c
 ├── elf_parse_shdr.c
 ├── elf_parse_shstrtab.c

include/
 └── elf_parser.h
```

---

## 10. 다른 모듈과의 인터페이스

### 입력

```c
const char *path
```

### 출력

```c
elf_t *elf
```

### 사용 예

```c
elf_t elf;

elf_parse("a.out", &elf);

/* 이후 */
check_mitigation(&elf);
analyze_symbols(&elf);
```

---

## 11. 확장 계획

* Symbol Table 파싱
* Relocation 분석
* DWARF 정보 처리
