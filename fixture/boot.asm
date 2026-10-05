; Project-authored harness fixture, NOT the oslab boot chain.
; A BIOS sector with COM1 protocol, intentional #UD and debug-exit.
bits 16
section .text
global _start, ready, fault, panic, hang
_start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    cld
    mov word [6*4], panic
    mov word [6*4+2], 0
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
    mov si, greeting
    call puts
ready:
    call getc
    cmp al, '1'
    jne ready
    call getc
    mov bl, al
.newline:
    call getc
    cmp al, 10
    jne .newline
    cmp bl, 'F'
    je fault
    cmp bl, 'H'
    je hang
    cmp bl, 'R'
    je reset
    cmp bl, 'B'
    je bad
    cmp bl, 'P'
    je calculate
    cmp bl, 'W'
    jne invalid
calculate:
    ; The fixture performs a real arithmetic assertion before reporting value 42.
    mov ax, 6
    mov cx, 7
    mul cx
    cmp ax, 42
    jne bad
    ; Format the actual computed quotient and remainder, not a canned result.
    mov cl, 10
    div cl
    add al, '0'
    add ah, '0'
    mov [digits], ax
    mov si, result
    call puts
    mov al, 0x10
    cmp bl, 'W'
    jne .exit
    inc al
.exit:
    mov dx, 0xf4
    out dx, al
    jmp silent_stop
invalid:
    mov si, invalid_msg
    call puts
    mov al, 0x11
    mov dx, 0xf4
    out dx, al
    jmp silent_stop
bad:
    mov si, bad_result
    call puts
    mov al, 0x10
    mov dx, 0xf4
    out dx, al
    jmp silent_stop
fault:
    ud2
panic:
    mov si, panic_msg
    call puts
    cli
.loop:
    hlt
    jmp .loop
hang:
    mov si, hang_msg
    call puts
    cli
.loop:
    hlt
    jmp .loop
reset:
    mov dx, 0x64
    mov al, 0xfe
    out dx, al
    jmp hang
silent_stop:
    cli
.loop:
    hlt
    jmp .loop
getc:
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 1
    jz .wait
    mov dx, 0x3f8
    in al, dx
    ret
puts:
    lodsb
    test al, al
    jz .done
    mov ah, al
    mov dx, 0xe9
    out dx, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov al, ah
    mov dx, 0x3f8
    out dx, al
    jmp puts
.done:
    ret
greeting: db 'OSE1 BOOT real16', 10, 'OSE1 LOG level=info fixture', 10, 'OSE1 READY', 10, 0
result: db 'OSE1 RESULT id=1 value='
digits: db '00', 10, 'OSE1 DONE', 10, 0
invalid_msg: db 'OSE1 ERROR unsupported-command', 10, 0
bad_result: db 'OSE1 RESULT id=1 value=41', 10, 'OSE1 DONE', 10, 0
panic_msg: db 'OSE1 PANIC vector=6', 10, 0
hang_msg: db 'OSE1 HANG', 10, 0
times 510-($-$$) db 0
dw 0xaa55
