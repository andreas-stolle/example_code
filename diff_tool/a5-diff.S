#ifdef MACOS
    .global _my_diff
    printf: jmp _printf
    malloc: jmp _malloc
    calloc: jmp _calloc
    realloc: jmp _realloc
    free: jmp _free
    fopen: jmp _fopen
    fclose: jmp _fclose 
    fgets: jmp _fgets
    fread: jmp _fread
    fprintf: jmp _fprintf
    fscanf: jmp _fscanf
    strcasecmp: jmp _strcasecmp
    strcmp: jmp _strcmp
    strcpy: jmp _strcpy
    strlen: jmp _strlen
    strncasecmp: jmp _strncasecmp
    strncmp: jmp _strncmp
    strncpy: jmp _strncpy
    strnlen: jmp _strnlen
    memset: jmp _memset
#else 
    .global my_diff
    _printf: jmp printf
    _malloc: jmp malloc
    _calloc: jmp calloc
    _realloc: jmp realloc
    _free: jmp free
    _fopen: jmp fopen
    _fclose: jmp fclose
    _fgets: jmp fgets
    _fread: jmp fread
    _fprintf: jmp fprintf
    _fscanf: jmp fscanf
    _strcasecmp: jmp strcasecmp
    _strcmp: jmp strcmp
    _strcpy: jmp strcpy
    _strlen: jmp strlen
    _strncasecmp: jmp strncasecmp
    _strncmp: jmp strncmp
    _strncpy: jmp strncpy
    _strnlen: jmp strnlen
    _memset: jmp memset
#endif

.bss
# [uninitialized static variables] 

.data
# [initialized static variables]
buffer_a: .zero 1024
buffer_b: .zero 1024 

.text
# [constants/strings]
changestring:
    .ascii "%dc%d\n"
    .ascii "< %s\n"
    .ascii "---\n"
    .asciz "> %s\n"

empty_line: .asciz "\n"

mode:
    .asciz "r"

# int my_diff(const char *a, const char *b, bool flag_i, bool flag_B)
_my_diff:
my_diff:
    # Implement me!
    pushq   %rbp                            # save previous base pointer
    movq    %rsp,           %rbp            # set base pointer for new stack frame
    
    subq    $96,            %rsp

    movq    %rdi,           -8(%rbp)         # pointer to a
    movq    %rsi,           -16(%rbp)        # pointer to b
    movq    %rdx,           -24(%rbp)        # flag_i
    movq    %rcx,           -32(%rbp)        # flag_B
    movq    $0,             -40(%rbp)        # line counter
    movq    $0,             -48(%rbp)        # opened file a
    movq    $0,             -56(%rbp)        # opened file b
    movq    $0,             -64(%rbp)        # state line a
    movq    $0,             -72(%rbp)        # state line b
    movq    $0,             -80(%rbp)        # return value
    movq    $1,             -88(%rbp)        # a end
    movq    $1,             -96(%rbp)        # b end

    movq    -8(%rbp),       %rdi            # file a into 1st arg   
    leaq    mode(%rip),     %rsi            # set mode to read 2nd arg
    call    fopen  
    movq    %rax,           -48(%rbp)        # opened file a

    movq    -16(%rbp),      %rdi            # file a into 1st arg   
    leaq    mode(%rip),     %rsi            # set mode to read 2nd arg
    call    fopen  
    movq    %rax,           -56(%rbp)        # opened file b

next_line:
    incq    -40(%rbp)                       # increase line counter

file_a:
    leaq    buffer_a(%rip), %rdi            # clear buffer
    movq    $0,             %rsi        
    movq    $1024,          %rdx
    call    memset

    leaq    buffer_a(%rip), %rdi            # create newline
    movq    $10,            %rsi
    movq    $1,             %rdx
    call    memset

    cmpq    $0,             -88(%rbp)       # check a end
    je      file_b

    leaq    buffer_a(%rip), %rdi            # get line a
    movq    $1024,          %rsi  
    movq    -48(%rbp),      %rdx
    call    fgets
    movq    %rax,           -64(%rbp)       # state line a
    movq    %rax,           -88(%rbp)       # set a end

    cmpq    $1,             -32(%rbp)       # check for B
    jne     file_b                          # if no B then read line b

    leaq    buffer_a(%rip), %rdi            # if there is B 
    cmpq    $10, (%rdi)                     # if line is blank
    je      file_a                          # read next line

file_b:
    leaq    buffer_b(%rip), %rdi            # clear buffer
    movq    $0,             %rsi        
    movq    $1024,          %rdx
    call    memset

    leaq    buffer_b(%rip), %rdi            # create newline
    movq    $10,            %rsi
    movq    $1,             %rdx
    call    memset

    cmpq    $0,             -96(%rbp)       # check b end  
    je      check_empty

    leaq    buffer_b(%rip), %rdi            # get line b
    movq    $1024,          %rsi  
    movq    -56(%rbp),      %rdx
    call    fgets
    movq    %rax,           -72(%rbp)       # state line b
    movq    %rax,           -96(%rbp)       # b end

    cmpq    $1,             -32(%rbp)       # check for B
    jne     check_empty                     # if not then jump 

    leaq    buffer_b(%rip), %rdi            # if there is B   
    cmpq    $10, (%rdi)                     # if line is blank
    je      file_b                          # read next line of b

check_empty:                                
    movq    -64(%rbp),      %rdi            # check if a is empty
    cmpq    $0,             %rdi
    je      a_zero                          # if it is jump

    jmp     basic_compare                   # it its not compare them

a_zero:
    movq    -72(%rbp),      %rdi            # check if b is empty
    cmpq    $0,             %rdi
    je      end                             # if it also is end

basic_compare:
    cmpq    $1,             -24(%rbp)       # if i flag jump to ignore case
    je      i_flag    

    leaq    buffer_a(%rip), %rdi
    leaq    buffer_b(%rip), %rsi
    call    strcmp
    jmp     cmp_result                      # jump over ignore case 

i_flag:                                     # compare with ignoring cases
    leaq    buffer_a(%rip), %rdi
    leaq    buffer_b(%rip), %rsi
    call    strcasecmp                  

cmp_result:
    cmpq    $0,             %rax
    je     equal                            # if returns zero jump to equal

remove_newline_a:                               
    leaq    buffer_a(%rip), %rdi            # load line
    call    strlen                          # get length
    leaq    buffer_a(%rip), %rdi            # load again into rdi
    dec     %rax                            # subtract 1 from rax to get coordinate of last char
    addq    %rax, %rdi                      # add rax to pointer to line a
    cmpq    $10,            (%rdi)          # if there is no a new line
    jne     remove_newline_b                # jump 
    movq    $0,             (%rdi)          # if there is remove it by replacing it with 0

remove_newline_b:
    leaq    buffer_b(%rip), %rdi
    call    strlen
    leaq    buffer_b(%rip), %rdi
    dec     %rax
    addq    %rax, %rdi
    cmpq    $10,            (%rdi)
    jne     print
    movq    $0,             (%rdi)
 
print:
    leaq    changestring(%rip),   %rdi
    movq    -40(%rbp),      %rsi  
    movq    -40(%rbp),      %rdx
    leaq    buffer_a(%rip), %rcx
    leaq    buffer_b(%rip), %r8
    movb    $0,             %al
    call    printf
    
    movq    $1,             -80(%rbp)

equal:
    jmp     next_line                       # start loop again with the next line

end:
    movq    -80(%rbp),      %rax            # set return value
    movq    %rbp,           %rsp            # reset stack pointer to bottom
    popq    %rbp                            # restore previous base pointer   
    ret
