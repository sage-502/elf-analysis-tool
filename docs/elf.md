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

```
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

| 필드 | 의미 | 내용 |
| ---- | ---- | ---- |
| e_ident | ELF인지 판별 + 기본 정보 | 매직넘버(0~3), 32bit/64bit(4), 엔디안(5), ELF 버전(6) |
| e_entry | 프로그램 시작 주소 | |
| e_phoff | Program


### 2.2 Program Header



### 2.3 Section Header



### 2.4 Section Data
