# 📄 ELF Parser 내부 설계(v2)

## 1. 개요

본 문서는 ELF 파서의 내부 설계를 정의한다.
외부 인터페이스는 유지하면서, 내부 구조를 **파일 I/O와 파싱 단계로 분리**하여 안정성과 확장성을 확보한다.

---

## 2. 전체 구조

### 2.1 흐름

```
[CLI]
  ↓ (파일 경로 입력)
parse_elf()
  ↓
 ├── open_elf()
 ├── init_elf()
 ├── read_file()
 ├── parse_ehdr()
 ├── parse_phdr()
 ├── parse_shdr()
  ↓
return elf_t*
```

---

## 3. 핵심 구조체

### 3.1 elf_t

ELF 파일 전체 상태를 담는 컨테이너 구조체

```c
typedef struct s_elf
{
    /* ELF Header */
    Elf64_Ehdr      ehdr;

    /* Program Header */
    Elf64_Phdr      *phdrs;
    int             phnum;

    /* Section Header */
    Elf64_Shdr      *shdrs;
    int             shnum;

    /* Section name string table */
    char            *shstrtab;

    /* Raw file data */
    unsigned char   *data;
    size_t          size;

} elf_t;
```

---

## 4. 설계 원칙

### 4.1 파일 I/O와 파싱 분리

* 파일 처리: `open`, `read`
* 구조 해석: `parse_*`

역할 분리를 통해 디버깅과 유지보수 용이


### 4.2 데이터 중심 구조

* 모든 데이터는 `elf_t`를 중심으로 관리
* 이후 함수들은 `elf_t *`만을 인자로 받음


### 4.3 fd 사용 범위 제한

* `fd`는 `parse_elf()` 내부에서만 사용
* 이후 모든 처리는 `elf->data` 기반


### 4.4 메모리 기반 파싱

* 파일을 통째로 메모리에 로드
* offset 기반으로 구조체 해석

```c
elf->ehdr = *(Elf64_Ehdr *)elf->data;
```

---

## 5. 기능별 역할

### 5.1 파일 I/O 계층

#### open_elf

```c
int open_elf(const char *filename);
```

* ELF 파일 열기
* 실패 시 에러 반환


#### get_file_size

```c
size_t get_file_size(int fd);
```

* `lseek`를 이용해 파일 크기 반환


#### read_file

```c
int read_file(int fd, elf_t *elf);
```

* 파일 전체를 `elf->data`에 저장
* `elf->size` 설정


### 5.2 초기화

#### init_elf

```c
elf_t *init_elf(void);
```

* `elf_t` 메모리 할당
* 구조체 초기화


### 5.3 파싱 계층

#### parse_ehdr

```c
void parse_ehdr(elf_t *elf);
```

* ELF Header 해석
* ELF magic 검사


#### parse_phdr

```c
void parse_phdr(elf_t *elf);
```

* Program Header 설정

```c
elf->phdrs = (Elf64_Phdr *)(elf->data + elf->ehdr.e_phoff);
```


#### parse_shdr

```c
void parse_shdr(elf_t *elf);
```

* Section Header 설정

```c
elf->shdrs = (Elf64_Shdr *)(elf->data + elf->ehdr.e_shoff);
```

---

## 6. 컨트롤러 함수

### parse_elf

```c
elf_t *parse_elf(const char *filename);
```

#### 역할

* 전체 파싱 흐름 제어
* 각 단계 함수 호출
* 최종 `elf_t` 반환

---

## 7. 처리 단계 정리

| 단계                | 설명            |
| ----------------- | ------------- |
| 파일 열기             | open_elf      |
| 크기 확인             | get_file_size |
| 파일 읽기             | read_file     |
| ELF Header 파싱     | parse_ehdr    |
| Program Header 파싱 | parse_phdr    |
| Section Header 파싱 | parse_shdr    |

---

## 8. 에러 처리 정책

### 현재 (개발 단계)

* `perror + exit` 사용
* 빠른 디버깅 목적

### 목표 (리팩토링 단계)

* 함수 내부: `return NULL / -1`
* main: 에러 출력 및 종료

---

## 9. 설계 장점

* 역할 분리로 가독성 향상
* 디버깅 용이
* 팀원 간 작업 분담 가능
* 확장성 확보 (symbol table, mitigation 등)

---

## 10. 향후 확장

* Symbol Table 파싱
* Dynamic Section 파싱
* Mitigation 분석 (NX, PIE, RELRO)
* 취약 함수 탐지

---

## 11. 최종 요약

> 본 설계는 ELF 파일을 메모리로 로드한 후,
> offset 기반으로 구조체를 해석하는 방식이며,
> 파일 I/O와 파싱 단계를 분리하여 안정성과 확장성을 확보한다.
