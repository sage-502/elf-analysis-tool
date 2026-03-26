# ELF 구조(x86 64bit 기준)

ELF는 Linux와 Unix에서 사용한는 실행 파일의 포맷이다.

별도의 확장자가 존재하지 않으며, 
* 실행 파일(Executable)
* 라이브러리(.so)
* 오브젝트 파일(.o)
을 모두 포함한다.

이 문서에서는 ELF의 구조를 알아본다.

---

## 1. 개요

ELF 파일의 기본 구조는 다음과 같다.

```
+---------------------------+
| ELF Header                |
+---------------------------+
| Program Header Table      |
+---------------------------+
| Section Header Table      |
+---------------------------+
| Section Data (.text 등)   |
+---------------------------+
```

ELF는 단순한 바이너리 파일이 아니라,
**여러 개의 구조체와 데이터 영역이 조합된 구조화된 포맷**이다.

각 영역은 서로 다른 목적을 가지며,
특히 **실행 관점과 분석 관점이 분리되어 있다는 점이 특징이다.**

> **노트 ─ Segment vs Section**
> 
> | 구분 | Segment (Program Header) | Section (Section Header) |
> | -- | ------------------------ | ------------------------ |
> | 기준 | 실행                       | 분석                       |
> | 사용 | loader                   | 분석 도구                    |
> | 구조 | 메모리 배치                   | 파일 구성                    |

이제부터는 `elf.h`에 구현되어 있는 실제 구조체들을 보며 각 영역에 정의되어 있는 필드를 알아본다.

---

## 2. 각 영역 별 주요 필드

### 2.1 ELF Header

#### 구조체
``` c
typedef struct
{
	unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
	Elf64_Half	e_type;			/* Object file type */
	Elf64_Half	e_machine;		/* Architecture */
	Elf64_Word	e_version;		/* Object file version */
	Elf64_Addr	e_entry;		/* Entry point virtual address */
	Elf64_Off	e_phoff;		/* Program header table file offset */
	Elf64_Off	e_shoff;		/* Section header table file offset */
	Elf64_Word	e_flags;		/* Processor-specific flags */
	Elf64_Half	e_ehsize;		/* ELF header size in bytes */
	Elf64_Half	e_phentsize;		/* Program header table entry size */
	Elf64_Half	e_phnum;		/* Program header table entry count */
	Elf64_Half	e_shentsize;		/* Section header table entry size */
	Elf64_Half	e_shnum;		/* Section header table entry count */
	Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;
```

#### 주요 필드

| 필드 | 의미 | 설명 |
| ---- | ---- | ---- |
| e_ident | ELF인지 판별 + 기본 정보 | 매직넘버(0~3), 32bit/64bit(4), 엔디안(5), ELF 버전(6) : 총 16bytes |
| e_entry | 프로그램 시작 주소 | |
| e_phoff | Program Header 시작 위치 (offset) | ProgramHeader = base + e_phoff |
| e_shoff | Section Header 시작 위치 (offset) | SectionHeader = base + e_shoff |
| e_phnum | Program Header 개수 | 메모리에 로드할 단위(세그먼트) 개수 |
| e_shnum | Section Header 개수 | 파일 내부 구성 요소(섹션) 개수 |
| e_shstrndx | 섹션 이름 페이블 위치 | Section Header 내부 배열(`shstr`)에서 `.shstrtab`이 있는 인덱스 |


### 2.2 Program Header

#### 구조체
``` c
typedef struct
{
	Elf64_Word	p_type;			/* Segment type */
	Elf64_Word	p_flags;		/* Segment flags */
	Elf64_Off	p_offset;		/* Segment file offset */
	Elf64_Addr	p_vaddr;		/* Segment virtual address */
	Elf64_Addr	p_paddr;		/* Segment physical address */
	Elf64_Xword	p_filesz;		/* Segment size in file */
	Elf64_Xword	p_memsz;		/* Segment size in memory */
	Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;
```

#### 주요 필드

| 필드       | 의미         | 설명                                                     |
| -------- | ---------- | ------------------------------------------------------ |
| p_type   | Segment 타입 | PT_LOAD(메모리 로드), PT_DYNAMIC(동적 링킹), PT_INTERP(인터프리터) 등 |
| p_flags  | Segment 권한 | PF_R(Read), PF_W(Write), PF_X(Execute)                 |
| p_offset | 파일에서 위치    | file_address = file_base + p_offset                    |
| p_vaddr  | 메모리 주소     | memory_address = base + p_vaddr                        |
| p_filesz | 파일에서 크기    | 실제 파일에 존재하는 데이터 크기                        |
| p_memsz  | 메모리에서 크기   | 메모리에 할당되는 크기 (보통 p_memsz ≥ p_filesz)        |
| p_align  | 정렬 단위      | 메모리 정렬 기준 (보통 0x1000, 페이지 단위)               |


### 2.3 Section Header

#### 구조체

``` c
typedef struct
{
	Elf64_Word	sh_name;		/* Section name (string tbl index) */
	Elf64_Word	sh_type;		/* Section type */
	Elf64_Xword	sh_flags;		/* Section flags */
	Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
	Elf64_Off	sh_offset;		/* Section file offset */
	Elf64_Xword	sh_size;		/* Section size in bytes */
	Elf64_Word	sh_link;		/* Link to another section */
	Elf64_Word	sh_info;		/* Additional section information */
	Elf64_Xword	sh_addralign;		/* Section alignment */
	Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf64_Shdr;
```

#### 주요 필드

| 필드           | 의미             | 설명                                   |
| ------------ | -------------- | -------------------------------------------------|
| sh_name      | 섹션 이름 (offset) | 문자열이 아니라 `.shstrtab`에서의 offset             |
| sh_type      | 섹션 타입          | SHT_PROGBITS(.text), SHT_SYMTAB, SHT_STRTAB, SHT_NOBITS(.bss) 등 |
| sh_flags     | 섹션 속성          | SHF_ALLOC(메모리 로드), SHF_WRITE(쓰기), SHF_EXECINSTR(실행)             |
| sh_addr      | 메모리 주소         | 실행 시 해당 Section이 올라가는 주소             |
| sh_offset    | 파일 위치 (offset) | section_data = base + sh_offset               |
| sh_size      | 섹션 크기          | 해당 Section의 전체 크기                       |
| sh_link      | 다른 섹션 참조       | 예: `.symtab` → `.strtab` 연결                  |
| sh_info      | 추가 정보          | Section별로 의미 다름 (보통 인덱스/정보값)           |
| sh_addralign | 정렬 단위          | 메모리 정렬 기준                                  |
| sh_entsize   | 엔트리 크기         | 테이블형 Section에서 각 entry 크기 (ex: symbol size)     |

> 실제 실행 시에는 Program Header(PT_LOAD)가 기준이 되며,
> Section은 분석을 위한 논리적 구분이다.

### 2.4 Section Data

Section Data는 각 Section에 해당하는 실제 데이터가 저장된 영역이다.

Section Header에서 정의된 sh_offset과 sh_size를 통해 접근할 수 있다. </br>
코드, 변수, 문자열 등 프로그램의 실제 내용이 포함된다.

대표적인 Section은 다음과 같다.

| Section   | 의미                    |
| --------- | --------------------- |
| `.text`   | 실행 코드                 |
| `.data`   | 초기화된 전역 변수            |
| `.bss`    | 초기화되지 않은 변수 (파일에는 없음) |
| `.rodata` | 읽기 전용 데이터             |
| `.symtab` | 심볼 테이블                |
| `.strtab` | 문자열 테이블               |

---

## 3. 예시 

짧은 소스코드를 컴파일한 뒤, readelf 결과와 실제 raw byte를 매핑시켜 본다.

#### 소스코드

``` c
#include <stdio.h>

int main() {
    printf("Hello, world!\n");
    return 0;
}
```

#### 컴파일 옵션
```
gcc -O0 -fno-pie -no-pie hello.c -o hello
```

#### hexdump

```
$ hexdump -C hello
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 3e 00 01 00 00 00  50 10 40 00 00 00 00 00  |..>.....P.@.....|
00000020  40 00 00 00 00 00 00 00  38 36 00 00 00 00 00 00  |@.......86......|
00000030  00 00 00 00 40 00 38 00  0d 00 40 00 1f 00 1e 00  |....@.8...@.....|
00000040  06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000050  40 00 40 00 00 00 00 00  40 00 40 00 00 00 00 00  |@.@.....@.@.....|
00000060  d8 02 00 00 00 00 00 00  d8 02 00 00 00 00 00 00  |................|
00000070  08 00 00 00 00 00 00 00  03 00 00 00 04 00 00 00  |................|
00000080  18 03 00 00 00 00 00 00  18 03 40 00 00 00 00 00  |..........@.....|
00000090  18 03 40 00 00 00 00 00  1c 00 00 00 00 00 00 00  |..@.............|
(생략)
```

### 3.1 ELF Header

```
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 3e 00 01 00 00 00  50 10 40 00 00 00 00 00  |..>.....P.@.....|
00000020  40 00 00 00 00 00 00 00  38 36 00 00 00 00 00 00  |@.......86......|
00000030  00 00 00 00 40 00 38 00  0d 00 40 00 1f 00 1e 00  |....@.8...@.....|
```

#### e_ident (0x00 ~ 0x0f)
```
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
```

* `7f 45 4c 46` : ELF magic
* 02 : 64bit
* 01 : little endian
* 01 : ELF version

#### e_type (0x10 ~ 0x11)
```
00000010  02 00 3e 00 01 00 00 00  50 10 40 00 00 00 00 00  |..>.....P.@.....|
```

* `02 00` → `0x0002` : ET_EXEC (실행파일)

#### e_machine (0x12 ~ 0x13)

* `3e 00` → `0x003e` : x86-64

#### e_version (0x14 ~ 0x17)

* `01 00 00 00` → `0x01` (현재 ELF 버전)

#### e_entry (0x18 ~ 0x1f)

* `50 10 40 00 00 00 00 00` → `0x0000000000401050` : 프로그램 시작 주소

#### e_phoff (0x20 ~ 0x27)

```
00000020  40 00 00 00 00 00 00 00  38 36 00 00 00 00 00 00  |@.......86......|
```

* `40 00 00 00 00 00 00 00` → `0x40` : Program Header 시작 위치 (offset)

#### e_shoff (0x28 ~ 0x2f)

* `38 36 00 00 00 00 00 00` → `0x3638` : Section Header Table 위치(offset)

#### e_flags (0x30 ~ 0x33)

```
00000030  00 00 00 00 40 00 38 00  0d 00 40 00 1f 00 1e 00  |....@.8...@.....|
```

* `00 00 00 00` → 0

#### e_ehsize (0x34 ~ 0x35)

* `40 00` → `0x40` (64bytes) : ELF header 크기

#### e_phentsize (0x36 ~ 0x37)

* `38 00` → `0x38` (56bytes) : Program Header 하나 크기

#### e_phnum (0x38 ~ 0x39)

* `0d 00` → `0x0d` (13개) : Program Header 개수 

#### e_shentsize (0x3a ~ 0x3b)

* `40 00` → `0x40` (64bytes) : Section header 하나 크기

#### e_shnum (0x3c ~ 0x3d)

* `1f 00` → `0x1f` (31개) : Section header 개수

#### e_shstrndx (0x3e ~ 0x3f)

* `1e 00` → `0x1e` (30) : section name string table index

### 3.2 Program Header (PT_LOAD)

Program Header는 여러 개가 같은 구조로 반복되므로 PT_LOAD 하나만 보도록 하겠다.

3번째 Program Header였다.

```
000000b0  01 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  |................|
000000c0  00 00 40 00 00 00 00 00  00 00 40 00 00 00 00 00  |..@.......@.....|
000000d0  f8 04 00 00 00 00 00 00  f8 04 00 00 00 00 00 00  |................|
000000e0  00 10 00 00 00 00 00 00
```

---

#### p_type (0x00 ~ 0x03)

```
000000b0  01 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  |................|
```

* `01 00 00 00` → `0x00000001` : **PT_LOAD**

#### p_flags (0x04 ~ 0x07)

* `04 00 00 00` → `0x4` : **R (Read only)**

#### p_offset (0x08 ~ 0x0f)

* `00 00 00 00 00 00 00 00` → `0x0` : 파일 시작부터 로딩

#### p_vaddr (0x10 ~ 0x17)

```
000000c0  00 00 40 00 00 00 00 00  00 00 40 00 00 00 00 00  |..@.......@.....|
```

* `00 00 40 00 00 00 00 00` → `0x0000000000400000` : 메모리 시작 주소

#### p_paddr (0x18 ~ 0x1f)

* `00 00 40 00 00 00 00 00` → `0x0000000000400000` (보통 vaddr와 동일)

#### p_filesz (0x20 ~ 0x27)

```
000000d0  f8 04 00 00 00 00 00 00  f8 04 00 00 00 00 00 00  |................|
```

* `f8 04 00 00 00 00 00 00` → `0x4f8` (1272 bytes)

#### p_memsz (0x28 ~ 0x2f)

* `f8 04 00 00 00 00 00 00` → `0x4f8` (메모리에서도 동일 크기)

#### p_align (0x30 ~ 0x37)

```
000000e0  00 10 00 00 00 00 00 00
```

* `00 10 00 00 00 00 00 00` → `0x1000` (4096) : 페이지 정렬

### 3.3  Section Header

우선 첫 번째 엔트리는 NULL 이다.
```
$ hexdump -C -s 0x3638 -n 0x40 hello
00003638  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00003678
```
전부 `00`으로 되어 있다.

Section Header는 .init 섹션 엔트리만 보도록 하겠다.

#### Section Header (.init) (offset 0x3938 ~ 0x3977)
```
00003938  a1 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  |................|
00003948  00 10 40 00 00 00 00 00  00 10 00 00 00 00 00 00  |..@.............|
00003958  1b 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00003968  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

#### sh_name (0x00 ~ 0x03)

```
00003938  a1 00 00 00 ...
```

* `a1 00 00 00` → `0xa1` : section name string table offset (".init")

#### sh_type (0x04 ~ 0x07)

* `01 00 00 00` → `SHT_PROGBITS`

#### sh_flags (0x08 ~ 0x0f)

```
00003938  ... 06 00 00 00 00 00 00 00
```

* `0x6` → ALLOC + EXEC (AX) → 실행 코드 영역

#### sh_addr (0x10 ~ 0x17)

```
00003948  00 10 40 00 00 00 00 00 ...
```

* `00 10 40 00 00 00 00 00` → `0x0000000000401000` : 메모리 주소

#### sh_offset (0x18 ~ 0x1f)

* `00 10 00 00 00 00 00 00` → `0x1000` : 파일 내 위치

#### sh_size (0x20 ~ 0x27)

```
00003958  1b 00 00 00 00 00 00 00 ...
```

* `1b 00 00 00 00 00 00 00` → `0x1b` (27 bytes)

#### sh_link (0x28 ~ 0x2b)

* `00 00 00 00` → 없음

#### sh_info (0x2c ~ 0x2f)

* `00 00 00 00` → 없음

#### sh_addralign (0x30 ~ 0x37)

```
00003968  04 00 00 00 00 00 00 00 ...
```

* `04 00 00 00 00 00 00 00` → `0x4` : alignment

#### sh_entsize (0x38 ~ 0x3f)

* `00 00 00 00 00 00 00 00` → 0 (entry 없음)

---

## 4. 실제 흐름

실제 동작 방식으로는 다음과 같은 절차로 Section Header가 어느 것의 엔트리인지 알아낸다.

1. `e_shstrndx` 확인
2. 그 index의 Section Header 찾기
3. 그 section의 `sh_offset` 찾기
4. 거기서 문자열 테이블 읽기
5. `sh_name` offset으로 문자열 추출

### 4.1 `e_shstrndx` 확인

앞서 ELF Header에서 `0x1e`임을 확인했다.

### 4.2 그 index의 Section Header 찾기

ELF Header에서 본 정보는 다음과 같다.
```
e_shoff     = 0x3638
e_shentsize = 0x40
e_shstrndx  = 0x1e (30)
```
따라서
```
offset = 0x3638 + (0x1e * 0x40)
	   = 0x3db8
```
Section Header[0x1e]의 위치는 0x3db8이다.

### 4.3 그 section의 `sh_offset` 찾기

이것이 section name string table (.shstrtab) 이다.

```
$ hexdump -C -s 0x3db8 -n 0x40 hello
00003db8  11 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  |................|
00003dc8  00 00 00 00 00 00 00 00  19 35 00 00 00 00 00 00  |.........5......|
00003dd8  1f 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00003de8  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

#### sh_offset
```
19 35 00 00 00 00 00 00 → 0x3519
```

이것이 문자열 테이블의 실제 위치이다.

#### sh_size

```
1f 01 00 00 00 00 00 00 → 0x11f (287 bytes)
```

그리고 문자열 전체 길이.

### 4.4 거기서 문자열 테이블 읽기

```
hexdump -C -s 0x3519 -n 0x11f hello
00003519  00 2e 73 79 6d 74 61 62  00 2e 73 74 72 74 61 62  |..symtab..strtab|
00003529  00 2e 73 68 73 74 72 74  61 62 00 2e 69 6e 74 65  |..shstrtab..inte|
00003539  72 70 00 2e 6e 6f 74 65  2e 67 6e 75 2e 70 72 6f  |rp..note.gnu.pro|
00003549  70 65 72 74 79 00 2e 6e  6f 74 65 2e 67 6e 75 2e  |perty..note.gnu.|
00003559  62 75 69 6c 64 2d 69 64  00 2e 6e 6f 74 65 2e 41  |build-id..note.A|
00003569  42 49 2d 74 61 67 00 2e  67 6e 75 2e 68 61 73 68  |BI-tag..gnu.hash|
00003579  00 2e 64 79 6e 73 79 6d  00 2e 64 79 6e 73 74 72  |..dynsym..dynstr|
00003589  00 2e 67 6e 75 2e 76 65  72 73 69 6f 6e 00 2e 67  |..gnu.version..g|
00003599  6e 75 2e 76 65 72 73 69  6f 6e 5f 72 00 2e 72 65  |nu.version_r..re|
000035a9  6c 61 2e 64 79 6e 00 2e  72 65 6c 61 2e 70 6c 74  |la.dyn..rela.plt|
000035b9  00 2e 69 6e 69 74 00 2e  70 6c 74 2e 73 65 63 00  |..init..plt.sec.|
000035c9  2e 74 65 78 74 00 2e 66  69 6e 69 00 2e 72 6f 64  |.text..fini..rod|
000035d9  61 74 61 00 2e 65 68 5f  66 72 61 6d 65 5f 68 64  |ata..eh_frame_hd|
000035e9  72 00 2e 65 68 5f 66 72  61 6d 65 00 2e 69 6e 69  |r..eh_frame..ini|
000035f9  74 5f 61 72 72 61 79 00  2e 66 69 6e 69 5f 61 72  |t_array..fini_ar|
00003609  72 61 79 00 2e 64 79 6e  61 6d 69 63 00 2e 67 6f  |ray..dynamic..go|
00003619  74 00 2e 67 6f 74 2e 70  6c 74 00 2e 64 61 74 61  |t..got.plt..data|
00003629  00 2e 62 73 73 00 2e 63  6f 6d 6d 65 6e 74 00     |..bss..comment.|
```

`0x3519`에서부터 `0x11f` 출력한 결과이다.
이것이 실제 문자열 테이블이다. 

### 4.5 `sh_name` offset으로 문자열 추출

섹션 3에서 .init 영역의 Section Header로 추정했던 엔트리의 `sh_name` 은 `0xa1` 이었다.

```
0x3519 + 0xa1 = 0x35ba
```

0x36ba를 출력해보면

```
$ hexdump -C -s 0x35ba -n 0x10 hello
000035ba  2e 69 6e 69 74 00 2e 70  6c 74 2e 73 65 63 00 2e  |.init..plt.sec..|
```

`.init`이 맞다.

---

## 5. 정리

ELF는 단순한 실행 파일이 아니라,
여러 구조체와 데이터 영역이 결합된 **구조화된 바이너리 포맷**이다.

전체 구조는 크게 다음과 같이 나뉜다.

* **ELF Header** : 파일의 전체 구조와 위치 정보를 담고 있는 메타데이터
* **Program Header (Segment)** : 실행 시 메모리에 어떻게 로드되는지를 정의
* **Section Header (Section)** : 파일 내부 구성 요소를 논리적으로 구분
* **Section Data** : 실제 코드, 데이터, 문자열 등이 저장된 영역

특히 ELF의 핵심 특징은
실행 관점과 분석 관점이 분리되어 있다는 점이다.

* 실행 시에는 Program Header (Segment) 기준으로 메모리에 로드되고
* 분석 시에는 Section Header (Section) 기준으로 내부 구조를 파악한다

---

## 6. References

* GNU C Library (glibc), elf.h
* https://www.gnu.org/software/libc/
