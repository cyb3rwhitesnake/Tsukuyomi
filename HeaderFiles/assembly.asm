EXTERN syscall_number:DWORD
EXTERN syscall_address:QWORD

.CODE

indirectSyscall proc
	mov r10, rcx
	mov eax, syscall_number
	push syscall_address
	ret
indirectSyscall endp

END