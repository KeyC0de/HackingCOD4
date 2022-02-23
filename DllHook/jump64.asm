.code

; jmps are relative to the instruction pointer
; to absolute jmp to an address we need to use `call` instead
; eg
;	call qword ptr[addressToJumpTo]
;		or
;	call register
jmp64 proc
	mov rax, rcx
	call rax
jmp64 endp

end
