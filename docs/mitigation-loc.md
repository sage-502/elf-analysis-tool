# ELF 보호 기법 (Mitigation)

Mitigation은 프로그램에서 발생할 수 있는 취약점 악용을 어렵게 만들거나 방지하기 위한 보안 보호 기법이다.</br>
대표적인 기법으로는 NX, PIE, Canary, RELRO, ASLR이 있다.

이 문서에서는 각 mitigation의 역할과 ELF 파일에서의 적용여부 판단 방법을 위주로 간략하게 서술한다.

※ ASLR은 ELF만 보고는 적용 여부를 확정할 수 없기 때문에 이 문서에서는 NX, PIE, Canary, RELRO 만을 다룬다.

## 1. NX (No-eXecute)

**스택/힙을 실행 불가능하게 만드는 보호기법**

- **역할**
    - 데이터 영역(stack, heap)에 있는 코드를 실행 못하게 막음
    - 즉, 쉘코드 삽입 공격 차단
- **ELF에서 확인**
    - Program Header 중 `PT_GNU_STACK` segment에서 확
    - `E` (execute) 권한 없으면 NX 활성화

---

## 2. PIE (Position Independent Executable)

**프로그램이 실행될 때마다 주소가 랜덤으로 바뀜**

- **역할**
    - 코드 영역(base address)을 랜덤화
    - ASLR 효과를 **메인 바이너리에도 적용**
- **ELF에서 확인**
    - ELF Header에서 확인
    - `e_type == ET_DYN` → PIE 적용

---

## 3. Canary (Stack Canary)

**스택 오버플로우 감지 장치**

- **역할**
    - 함수 리턴 전에 canary 값 검사
    - 값이 바뀌면 프로그램 종료
- **ELF에서 확인**
    - Section Header Table의 `.dynsym` 에서 확인
    - `__stack_chk_fail` 혹은 `__stack_chk_guard` 심볼 존재 여부

```
Section Header Table
 ├── .dynsym   ← 여기서 심볼 목록
 ├── .dynstr   ← 문자열 테이블
```

※ 정적 링크의 경우 심볼이 안 보일 수도 있음.

---

## 4. RELRO (Relocation Read-Only)

**GOT(Global Offset Table) 보호**

- **종류**
    1. Partial RELRO
    2. Full RELRO
- **ELF에서 확인**
    - Program Header 중 `PT_GNU_RELRO` segment 존재
          - RELRO가 적용된 ELF에만 나타남. 최소 Partial RELRO
    - `PT_GNU_RELRO` segment에 `BIND_NOW` 있으면 Full RELRO

### Partial RELRO

- GOT 일부만 보호
- `.got.plt`는 writable
- 공격 가능: GOT overwrite 가능

### Full RELRO

- GOT 전체를 read-only로 변경
- 공격 차단: GOT overwrite 불가능

---

## 정리

| Mitigation | 막는 것 | 핵심 포인트 |
| --- | --- | --- |
| NX | 쉘코드 실행 | stack 실행 금지 |
| PIE | 주소 고정 공격 | base 주소 랜덤 |
| Canary | ret overwrite | 스택 무결성 체크 |
| RELRO | GOT overwrite | GOT 보호 |
