; Project-authored CPU-mode debug fixtures. No OS services or guest agent.
bits 16
section .text
global _start, protected_entry, hold
_start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    cld
    in al, 0x92
    or al, 2
    out 0x92, al
    lgdt [gdtr]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:protected_entry
bits 32
protected_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x90000
%ifndef TARGET32
    xor eax, eax
    mov edi, 0x1000
    mov ecx, 3072
    rep stosd
    mov dword [0x1000], 0x2003
    mov dword [0x2000], 0x3003
    mov edi, 0x3000
    mov eax, 0x83
    mov ecx, 512
.pages:
    mov [edi], eax
    add eax, 0x200000
    add edi, 8
    loop .pages
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax
    mov eax, 0x1000
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x100
    wrmsr
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
    jmp 0x18:long_entry
bits 64
global long_entry
long_entry:
    mov rsp, 0x90000
%endif
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 1
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 3
    out dx, al
%ifdef TARGET32
    mov esi, message
%else
    mov rsi, message
%endif
.print:
    lodsb
    test al, al
    jz hold
    mov ah, al
    mov dx, 0xe9
    out dx, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    jmp .print
hold:
    pause
    jmp hold
%ifdef TARGET32
message: db 'OSE1 MODE protected32', 10, 0
%else
message: db 'OSE1 MODE long64', 10, 0
%endif
align 8
gdt:
    dq 0
    dq 0x00cf9a000000ffff
    dq 0x00cf92000000ffff
    dq 0x00af9a000000ffff
gdtr:
    dw gdtr-gdt-1
    dd gdt
times 510-($-$$) db 0
dw 0xaa55
