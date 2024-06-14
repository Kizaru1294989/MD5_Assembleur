section .bss
    temp_buffer resb 64       ; Réservation de 64 octets pour le tampon temporaire
    hash_state resd 4         ; Réservation de 4 mots (32 bits chacun) pour l'état du hachage
    input_data resb 128       ; Réservation de 128 octets pour les données d'entrée
    final_hash resb 33        ; Réservation de 33 octets pour le résultat du hachage (32 + 1 pour le terminateur nul)
    user_input resb 128       ; Réservation de 128 octets pour l'entrée utilisateur
    input_length resd 1       ; Réservation de 4 octets pour la longueur de l'entrée

section .data
    hex_chars db "0123456789abcdef", 0
    prompt_msg db "Please enter a string to hash: ", 0

section .text
global _start
global perform_md5

_start:
    ; Afficher le message d'invite
    mov rax, 1                ; syscall: write
    mov rdi, 1                ; fichier: stdout
    lea rsi, [prompt_msg]     ; tampon: prompt_msg
    mov rdx, 30               ; taille du message
    syscall

    ; Lire les données de l'utilisateur
    mov rax, 0                ; syscall: read
    mov rdi, 0                ; fichier: stdin
    mov rsi, user_input       ; tampon: user_input
    mov rdx, 128              ; taille maximale de l'entrée
    syscall

    ; Calculer la longueur de l'entrée
    lea rdi, [user_input]
    xor r11, r11

length_user_calcul:
    cmp byte [rdi + r11], 0
    je length_user_calcul_result
    inc r11
    jmp length_user_calcul

length_user_calcul_result:
    mov [input_length], r11

    ; Copier les données de l'entrée dans le tampon de message
    lea rdi, [input_data]
    lea rsi, [user_input]
    mov rcx, [input_length]
    rep movsb

    ; Initialiser l'état du hachage
    mov dword [hash_state], 0x67452301
    mov dword [hash_state + 4], 0xefcdab89
    mov dword [hash_state + 8], 0x98badcfe
    mov dword [hash_state + 12], 0x10325476

    ; Effectuer la transformation MD5
    lea rdi, [input_data]
    mov rsi, rcx
    lea rdx, [hash_state]
    call perform_md5

    ; Convertir l'état du hachage en chaîne hexadécimale
    lea rdi, [hash_state]
    lea rsi, [final_hash]
    call to_hex_string

    ; Afficher le résultat
    mov rax, 1                ; syscall: write
    mov rdi, 1                ; fichier: stdout
    lea rsi, [final_hash]     ; tampon: final_hash
    mov rdx, 32               ; taille du tampon
    syscall

    ; Quitter le programme
    mov rax, 60               ; syscall: exit
    xor rdi, rdi
    syscall

perform_md5:
    ; Entrées:
    ; rdi - adresse des données du message
    ; rsi - longueur des données
    ; rdx - adresse de l'état du hachage
    ; Réserver l'espace pour le bloc de données
    push r10
    push r11

    ; Initialiser les variables locales
    sub rsp, 64
    lea r11, [rsp]
    xor r10, r10

    ; Copier le message dans le bloc
    mov rcx, rsi
    lea rsi, [rdi]
    lea rdi, [r11]
    rep movsb

    ; Ajouter le padding au bloc de données
    mov byte [r11 + rcx], 0x80
    inc rcx
    xor rax, rax
    lea rdi, [r11 + rcx]
    mov rsi, 56
    sub rsi, rcx
    rep stosb

    ; Ajouter la longueur du message en bits
    mov rax, [input_length]
    shl rax, 3
    mov [r11 + 56], rax

    lea rdi, [r11]
    lea rsi, [rdx]
    call md5_compression

    ; Restaurer la pile et retourner
    add rsp, 64
    pop r11
    pop r10
    ret

md5_compression:
    ; Sauvegarder les registres utilisés
    push r12
    push r13

    lea r12, [rdi]
    lea r13, [rsi]

    ; Charger l'état initial dans les registres
    mov eax, dword [r13]        ; a
    mov ebx, dword [r13 + 4]    ; b
    mov ecx, dword [r13 + 8]    ; c
    mov edx, dword [r13 + 12]   ; d

    ; Définir les macros pour les étapes de hachage
    %macro RI 7
        mov esi, %3
        add esi, dword [%5 * 4 + r12]
        xor esi, %4
        and esi, %2
        xor esi, %4
        add esi, %1
        rol esi, %6
        add esi, %2
        mov %1, esi
    %endmacro

    %macro RII 7
        mov esi, %4
        mov edi, %4
        add esi, dword [%5 * 4 + r12]
        not esi
        and edi, %2
        and esi, %3
        or edi, esi
        add edi, %1
        rol edi, %6
        add edi, %2
        mov %1, edi
    %endmacro

    %macro RIII 7
        mov esi, %3
        add esi, dword [%5 * 4 + r12]
        xor esi, %4
        xor esi, %2
        add esi, %1
        rol esi, %6
        add esi, %2
        mov %1, esi
    %endmacro

    %macro RIV 7
        mov esi, %4
        not esi
        add esi, dword [%5 * 4 + r12]
        or esi, %2
        xor esi, %3
        add esi, %1
        rol esi, %6
        add esi, %2
        mov %1, esi
    %endmacro

    ; 64 étapes de transformation MD5
    RI eax, ebx, ecx, edx, 0, 7, 0xd76aa478
    RI edx, eax, ebx, ecx, 1, 12, 0xe8c7b756
    RI ecx, edx, eax, ebx, 2, 17, 0x242070db
    RI ebx, ecx, edx, eax, 3, 22, 0xc1bdceee
    RI eax, ebx, ecx, edx, 4, 7, 0xf57c0faf
    RI edx, eax, ebx, ecx, 5, 12, 0x4787c62a
    RI ecx, edx, eax, ebx, 6, 17, 0xa8304613
    RI ebx, ecx, edx, eax, 7, 22, 0xfd469501
    RI eax, ebx, ecx, edx, 8, 7, 0x698098d8
    RI edx, eax, ebx, ecx, 9, 12, 0x8b44f7af
    RI ecx, edx, eax, ebx, 10, 17, 0xffff5bb1
    RI ebx, ecx, edx, eax, 11, 22, 0x895cd7be
    RI eax, ebx, ecx, edx, 12, 7, 0x6b901122
    RI edx, eax, ebx, ecx, 13, 12, 0xfd987193
    RI ecx, edx, eax, ebx, 14, 17, 0xa679438e
    RI ebx, ecx, edx, eax, 15, 22, 0x49b40821

    RII eax, ebx, ecx, edx, 1, 5, 0xf61e2562
    RII edx, eax, ebx, ecx, 6, 9, 0xc040b340
    RII ecx, edx, eax, ebx, 11, 14, 0x265e5a51
    RII ebx, ecx, edx, eax, 0, 20, 0xe9b6c7aa
    RII eax, ebx, ecx, edx, 5, 5, 0xd62f105d
    RII edx, eax, ebx, ecx, 10, 9, 0x02441453
    RII ecx, edx, eax, ebx, 15, 14, 0xd8a1e681
    RII ebx, ecx, edx, eax, 4, 20, 0xe7d3fbc8
    RII eax, ebx, ecx, edx, 9, 5, 0x21e1cde6
    RII edx, eax, ebx, ecx, 14, 9, 0xc33707d6
    RII ecx, edx, eax, ebx, 3, 14, 0xf4d50d87
    RII ebx, ecx, edx, eax, 8, 20, 0x455a14ed
    RII eax, ebx, ecx, edx, 13, 5, 0xa9e3e905
    RII edx, eax, ebx, ecx, 2, 9, 0xfcefa3f8
    RII ecx, edx, eax, ebx, 7, 14, 0x676f02d9
    RII ebx, ecx, edx, eax, 12, 20, 0x8d2a4c8a

    RIII eax, ebx, ecx, edx, 5, 4, 0xfffa3942
    RIII edx, eax, ebx, ecx, 8, 11, 0x8771f681
    RIII ecx, edx, eax, ebx, 11, 16, 0x6d9d6122
    RIII ebx, ecx, edx, eax, 14, 23, 0xfde5380c
    RIII eax, ebx, ecx, edx, 1, 4, 0xa4beea44
    RIII edx, eax, ebx, ecx, 4, 11, 0x4bdecfa9
    RIII ecx, edx, eax, ebx, 7, 16, 0xf6bb4b60
    RIII ebx, ecx, edx, eax, 10, 23, 0xbebfbc70
    RIII eax, ebx, ecx, edx, 13, 4, 0x289b7ec6
    RIII edx, eax, ebx, ecx, 0, 11, 0xeaa127fa
    RIII ecx, edx, eax, ebx, 3, 16, 0xd4ef3085
    RIII ebx, ecx, edx, eax, 6, 23, 0x04881d05
    RIII eax, ebx, ecx, edx, 9, 4, 0xd9d4d039
    RIII edx, eax, ebx, ecx, 12, 11, 0xe6db99e5
    RIII ecx, edx, eax, ebx, 15, 16, 0x1fa27cf8
    RIII ebx, ecx, edx, eax, 2, 23, 0xc4ac5665

    RIV eax, ebx, ecx, edx, 0, 6, 0xf4292244
    RIV edx, eax, ebx, ecx, 7, 10, 0x432aff97
    RIV ecx, edx, eax, ebx, 14, 15, 0xab9423a7
    RIV ebx, ecx, edx, eax, 5, 21, 0xfc93a039
    RIV eax, ebx, ecx, edx, 12, 6, 0x655b59c3
    RIV edx, eax, ebx, ecx, 3, 10, 0x8f0ccc92
    RIV ecx, edx, eax, ebx, 10, 15, 0xffeff47d
    RIV ebx, ecx, edx, eax, 1, 21, 0x85845dd1
    RIV eax, ebx, ecx, edx, 8, 6, 0x6fa87e4f
    RIV edx, eax, ebx, ecx, 15, 10, 0xfe2ce6e0
    RIV ecx, edx, eax, ebx, 6, 15, 0xa3014314
    RIV ebx, ecx, edx, eax, 13, 21, 0x4e0811a1
    RIV eax, ebx, ecx, edx, 4, 6, 0xf7537e82
    RIV edx, eax, ebx, ecx, 11, 10, 0xbd3af235
    RIV ecx, edx, eax, ebx, 2, 15, 0x2ad7d2bb
    RIV ebx, ecx, edx, eax, 9, 21, 0xeb86d391

    ; Mettre à jour l'état avec les résultats
    add dword [r13], eax
    add dword [r13 + 4], ebx
    add dword [r13 + 8], ecx
    add dword [r13 + 12], edx

    ; Restaurer les registres et retourner
    pop r13
    pop r12
    ret

to_hex_string:
    ; rdi - adresse de l'état
    ; rsi - adresse de la chaîne résultat
    mov rcx, 16
    xor r8, r8

hex_conversion_loop:
    mov al, byte [rdi + r8]
    mov ah, al
    shr al, 4
    and al, 0x0F
    add al, '0'
    cmp al, '9'
    jle skip_adjust_hex
    add al, 7

skip_adjust_hex:
    mov [rsi + r8 * 2], al
    
    mov al, ah
    and al, 0x0F
    add al, '0'
    cmp al, '9'
    jle skip_adjust_hex2
    add al, 7

skip_adjust_hex2:
    mov [rsi + r8 * 2 + 1], al

    inc r8
    loop hex_conversion_loop

    mov byte [rsi + 32], 0
    ret
