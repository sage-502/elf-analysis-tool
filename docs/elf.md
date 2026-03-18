# ELF 구조

ELF는 Linux와 Unix에서 사용한는 실행 파일의 포맷이다.

별도의 확장자가 존재하지 않으며, 
* 실행 파일(Executable)
* 라이브러리(.so)
* 오브젝트 파일(.o)
을 모두 포함한다.

이 문서에서는 ELF의 구조를 알아본다.

※ x86 64bit

---

## 1. 기본 구조

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

### 1.1 ELF Header

ELF 파일의 가장 앞에 위치하며,
파일 전체를 해석하기 위한 기본 정보를 제공한다.

주요 역할:

* ELF 파일 여부 확인 (Magic Number)
* 32bit / 64bit 구분
* Entry Point 주소
* Program Header / Section Header 위치 정보

ELF를 파싱할 때 반드시 가장 먼저 읽어야 한다.

### 1.2 Program Header

프로그램이 실행될 때,
파일을 메모리에 어떻게 배치할지를 정의한다.

주요 특징:

* loader가 사용
* Segment 단위로 구성
* 실행과 직접적인 관련 있음

실행 관점에서 가장 중요한 구조

### 1.3 Section Header

파일 내부의 논리적 구조를 정의한다.

주요 역할:

* 코드 / 데이터 / 심볼 분리
* 각 Section의 위치 및 속성 정의

분석 도구(readelf, objdump 등)가 사용

## 1.4 Sections

Section은 실제 데이터가 저장되는 영역이다.

대표적인 Section은 다음과 같다.

| Section         | 의미             |
| --------------- | -------------- |
| `.text`         | 실행 코드          |
| `.data`         | 초기화된 전역 변수     |
| `.bss`          | 초기화되지 않은 변수    |
| `.rodata`       | 읽기 전용 데이터 (상수) |
| `.symtab`       | 심볼 테이블         |
| `.strtab`       | 문자열 테이블        |
| `.plt` / `.got` | 동적 링킹 관련       |

Section은 파일 구조를 이해하는 데 핵심이다.

---

## 2. ELF Header

ELF Header는 파일의 시작 부분에 위치하며,
ELF 파일을 해석하기 위한 모든 기본 정보를 담고 있다.

이 구조체를 기반으로
Program Header와 Section Header에 접근할 수 있다.


### 2.1 구조체

```c
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];
  Elf64_Half	e_type;
  Elf64_Half	e_machine;
  Elf64_Word	e_version;
  Elf64_Addr	e_entry;
  Elf64_Off	e_phoff;
  Elf64_Off	e_shoff;
  Elf64_Word	e_flags;
  Elf64_Half	e_ehsize;
  Elf64_Half	e_phentsize;
  Elf64_Half	e_phnum;
  Elf64_Half	e_shentsize;
  Elf64_Half	e_shnum;
  Elf64_Half	e_shstrndx;
} Elf64_Ehdr;
```

ELF Header에서 중요한 것은
**파일 해석의 기준을 제공한다**는 점이다.

* offset 기반 구조
* 이후 모든 파싱의 출발점

### 2.2 `e_ident`

ELF 파일의 식별 정보와 기본 설정을 담고 있다.

가장 중요한 필드이며,
이 값을 통해 ELF 파일 여부를 판단할 수 있다.

#### 주요 역할

* ELF 파일인지 확인
* 32bit / 64bit 결정
* Endianness 결정

#### 주요 값

| 인덱스 | 의미                                |
| --- | --------------------------------- |
| 0~3 | `0x7f 'E' 'L' 'F'` (Magic Number) |
| 4   | 32bit / 64bit                     |
| 5   | Endianness                        |
| 6   | ELF Version                       |

### 특징

* 크기는 항상 16바이트 (`EI_NIDENT`)
* ELF 파싱의 첫 단계에서 반드시 확인해야 함

### 2.3 `e_entry`

프로그램 실행 시 가장 먼저 실행되는 주소이다.

```c
entry = e_entry;
```

loader는 이 주소로 점프하여 프로그램을 시작한다.

### 2.4 `e_phoff` / `e_shoff`

각 Header Table의 시작 위치를 나타낸다.

| 필드      | 의미                       |
| ------- | ------------------------ |
| e_phoff | Program Header 시작 offset |
| e_shoff | Section Header 시작 offset |

이 값들은 **파일 기준 offset**이다.

```c
phdr = base + e_phoff;
shdr = base + e_shoff;
```

base는 파일이 메모리에 매핑된 시작 주소이다.

### 2.5 `e_phnum` / `e_shnum`

각 Header의 개수를 나타낸다.

| 필드      | 의미                |
| ------- | ----------------- |
| e_phnum | Program Header 개수 |
| e_shnum | Section Header 개수 |

이 값들을 통해 반복문으로 각 구조체를 순회할 수 있다.

### 2.5 `e_shstrndx`

Section 이름 문자열 테이블의 위치를 나타낸다.

이 값은 **Section Header 배열에서의 인덱스**이다.

```c
shstr = shdr[e_shstrndx];
```

`.shstrtab`을 가리킨다.

---

## 3. Program Header

Program Header는 ELF 파일을 **메모리에 어떻게 로드할지 정의하는 구조**이다.

ELF Header가 파일의 전체 정보를 담고 있다면,
Program Header는 **실행 시 실제로 사용되는 정보**를 담고 있다.

이 정보는 loader가 사용하며,
프로그램이 실행될 때 메모리에 어떤 방식으로 배치될지를 결정한다.

### 3.1 구조체

```c
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

### 3.2 `p_type`

Segment의 종류를 나타낸다.

| 값          | 의미                                       |
| ---------- | ---------------------------------------- |
| PT_LOAD    | 메모리에 로드되는 세그먼트                           |
| PT_DYNAMIC | 동적 링킹 정보                                 |
| PT_INTERP  | 인터프리터 경로 (`/lib64/ld-linux-x86-64.so.2`) |
| PT_NOTE    | 부가 정보                                    |
| PT_PHDR    | Program Header 자체                        |

**PT_LOAD가 가장 중요하다**
실제로 메모리에 올라가는 영역이다.

---

#### 3.2.2 `p_offset` / `p_vaddr`

파일과 메모리를 연결하는 핵심 필드이다.

| 필드       | 의미          |
| -------- | ----------- |
| p_offset | 파일에서의 위치    |
| p_vaddr  | 메모리에 올라갈 주소 |

이 둘의 관계를 통해 loader는 파일 내용을 메모리에 배치한다.

```c
file_address   = file_base + p_offset;
memory_address = base + p_vaddr;
```

👉 즉,
**파일의 특정 위치가 메모리의 특정 주소로 매핑된다.**

---

#### 3.2.3 `p_filesz` / `p_memsz`

| 필드       | 의미           |
| -------- | ------------ |
| p_filesz | 파일에 존재하는 크기  |
| p_memsz  | 메모리에 할당되는 크기 |

일반적으로 `p_memsz >= p_filesz`이다.

이 차이는 `.bss`와 관련이 있다.

👉 `.bss`는 파일에는 저장되지 않지만
👉 메모리에서는 공간이 필요하기 때문에
👉 `p_memsz`가 더 크게 설정된다.

---

#### 3.2.4 `p_flags`

Segment의 권한을 나타낸다.

| 값    | 의미      |
| ---- | ------- |
| PF_R | Read    |
| PF_W | Write   |
| PF_X | Execute |

예시:

| 영역         | 권한    |
| ---------- | ----- |
| 코드(.text)  | R + X |
| 데이터(.data) | R + W |

---

#### 3.2.5 `p_align`

메모리 정렬 단위이다.
일반적으로 페이지 크기(0x1000) 단위로 정렬된다.

---

### 3.3 동작 원리 (Loader 관점)

loader는 Program Header를 순회하면서
각 Segment를 메모리에 로드한다.

```c
for (i = 0; i < e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD) {
        mmap(base + phdr[i].p_vaddr, phdr[i].p_memsz);
        memcpy(base + phdr[i].p_vaddr,
               file_base + phdr[i].p_offset,
               phdr[i].p_filesz);
    }
}
```

이 과정을 통해 프로그램이 실행 가능한 상태로 만들어진다.

---

### 3.4 특징

#### 1) 실행 시에는 Section을 사용하지 않는다

loader는 Section Header를 참고하지 않고,
오직 Program Header만 사용한다.

👉 즉, 실행 관점에서는
**Segment(Program Header)가 핵심 구조이다.**

---

#### 2) 여러 Section이 하나의 Segment로 묶인다

예를 들어:

| Section            | Segment     |
| ------------------ | ----------- |
| `.text`, `.rodata` | 하나의 PT_LOAD |
| `.data`, `.bss`    | 다른 PT_LOAD  |

👉 Section은 논리적 구조
👉 Segment는 실제 메모리 구조
