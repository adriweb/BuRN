.equ ANCHOR_LEN_WORD,  0x8D24
.equ ANCHOR_OLD_LEN,   0x03DD
.equ ANCHOR_FINAL_LEN, 0x03D9
.equ TARGET_BASE,      0x90FF
.equ TARGET_CONTENT,   0x9101
.equ RAW_ENTRY,        0x9104

.equ pTemp,            0x8D18
.equ symTable,         0xFE6E
.equ FPBase,           0x8D0C
.equ FPS,              0x8D0E
.equ OPS,              0x8D12
.equ curRow,           0x800C
.equ curCol,           0x800D
.equ grafCurs,         0x8215

.equ editFlags,        1
.equ editOpen,         2
.equ apdFlags,         8
.equ apdAble,          2
.equ appFlags,         13
.equ appTextSave,      1
.equ sGrFlags,         20
.equ textFlags,        5
.equ textInverse,      3
.equ textWrite,        7

.ifndef BURN_ROM_PROFILE
.equ BURN_ROM_PROFILE, 1900
.endif

.if BURN_ROM_PROFILE == 1900
.equ ROM_GET_CSC,      0x01D4
.equ ROM_FORCE_CMD,    0x033C
.equ ROM_MEMCHK,       0x20C5
.equ ROM_INSERT_MEM,   0x2272
.equ ROM_DEL_MEM,      0x25A7
.equ ROM_CLOSE_EDIT,   0x2EEE
.equ ROM_CLR_WINDOW,   0x37CA
.equ ROM_CLR_LCD_FULL, 0x38B4
.equ ROM_RUN_INDIC_OFF, 0x3932
.equ ROM_RUN_INDIC_ON, 0x394A
.equ ROM_GRBUFCPY,     0x38C6
.equ ROM_PUT_S,        0x3914
.equ ROM_KEY_HAND,     0x393E
.equ ROM_PUT_C,        0x39EC
.elseif BURN_ROM_PROFILE == 19006
.equ ROM_GET_CSC,      0x01F3
.equ ROM_FORCE_CMD,    0x038F
.equ ROM_MEMCHK,       0x21F0
.equ ROM_INSERT_MEM,   0x239D
.equ ROM_DEL_MEM,      0x26D2
.equ ROM_CLOSE_EDIT,   0x3031
.equ ROM_CLR_WINDOW,   0x3A45
.equ ROM_CLR_LCD_FULL, 0x39CD
.equ ROM_RUN_INDIC_OFF, 0x3A6F
.equ ROM_RUN_INDIC_ON, 0x3A93
.equ ROM_GRBUFCPY,     0x39DF
.equ ROM_PUT_S,        0x3A2D
.equ ROM_KEY_HAND,     0x3A87
.equ ROM_PUT_C,        0x3B35
.else
/* ROMs 15.0, 16.0, 17.0 and 18.0 share this fixed-page ABI. */
.equ ROM_GET_CSC,      0x01D4
.equ ROM_FORCE_CMD,    0x033C
.equ ROM_MEMCHK,       0x20AB
.equ ROM_INSERT_MEM,   0x2258
.equ ROM_DEL_MEM,      0x258D
.equ ROM_CLOSE_EDIT,   0x2ED4
.equ ROM_CLR_WINDOW,   0x37B0
.equ ROM_CLR_LCD_FULL, 0x389A
.equ ROM_RUN_INDIC_OFF, 0x3918
.equ ROM_RUN_INDIC_ON, 0x3930
.equ ROM_GRBUFCPY,     0x38AC
.equ ROM_PUT_S,        0x38FA
.equ ROM_KEY_HAND,     0x3924
.equ ROM_PUT_C,        0x39D2
.endif

.equ KEY_DOWN,         0x01
.equ KEY_LEFT,         0x02
.equ KEY_RIGHT,        0x03
.equ KEY_UP,           0x04
.equ KEY_ENTER,        0x09
.equ KEY_CLEAR,        0x0F
.equ KEY_MODE,         0x37

.equ PAGE_ROWS,        6
.equ MOVE_CHUNK,       7
.section .text, "ax"
.global burn_start
.global burn_end

/* The preserved BASIC parser exploit enters the native shell at $8D4E. */
burn_start:
    jp shell_main

/* The BASIC exploit reparses this byte; keep it zero between native runs. */
move_buffer:                   /* $8D51..$8D57: 7 bytes owned by BuRN */
.space MOVE_CHUNK,0
move_buffer_end:
.equ display_index, move_buffer+1

compare_hl_bc:
    push hl
    or a
    sbc hl,bc
    pop hl
    ret

random_7bit:
    /* Rotate-add state has a 244-call cycle with balanced high/low decisions.
       SRL returns 0..127 and exposes the discarded bit as pseudorandom carry. */
    ld a,0xA6
    add a,a
    adc a,0x3C
    ld (random_7bit+1),a
    srl a
    ret

/* BuRN's live allocation makes the OS key handler safe; retain CrASH's
   documented key-scan reset before entering it. */
cr_khand_runtime:
    res 4,(iy+9)
    jp ROM_KEY_HAND

.if (0x8D70 - 0x8D4E - (. - burn_start)) > 0
.space 0x8D70 - 0x8D4E - (. - burn_start), 0
.endif

/* CrASH 1.6 public state and fixed-entry ABI retained for compatible code. */

apd_free:                      /* $8D70 */
    .word 0x0300
int_state:                     /* $8D72 */
    .byte 0
crash_ver:                     /* $8D73 */
    .byte 0x16

rom_call_entry:                /* $8D74 */
    jp rom_call_dispatch

/* Preserve the registers touched by the OS copy; its implementation leaves IX
   alone, matching CrASH's documented AF/BC/DE/HL/IX preservation contract. */
graph_copy:                    /* $8D77..$8D86: unreachable fixed-ABI gap */
    push af
    push bc
    push de
    push hl
    call ROM_GRBUFCPY
    pop hl
    pop de
    pop bc
    pop af
    ret
.if BURN_ROM_PROFILE == 19006
/* The fixed-entry ABI leaves five otherwise unreachable bytes here.  Start
   the bounded classic/Ash CALL scan in that gap; its body follows the dispatcher. */
classic_patch_calls:
    ld a,b
    or a
    jp .ash_patch_check
.else
.space 0x8D88 - 0x8D4E - (. - burn_start), 0
.endif

exit_2_tios:                   /* $8D88 */
    jp target_forced_exit
rand_entry:                    /* $8D8B */
    jp random_7bit
cp_hl_bc_entry:                /* $8D8E */
    jp compare_hl_bc
cr_khand_entry:                /* $8D91 */
    jp cr_khand_runtime
grb_copy_entry:                /* $8D94 */
    jp graph_copy

/*
 * Dynamic dispatcher for the pre-19.0 SDK call offsets exercised here.
 * Main AF/BC/DE/HL reach the ROM routine unchanged; alternate registers are
 * private scratch.  The double-RET stack shape avoids modifying shell code.
 */
rom_call_dispatch:
    ex af,af'
    exx
    pop hl
    ld e,(hl)
    inc hl
    ld d,(hl)
    inc hl
    push hl
.if BURN_ROM_PROFILE == 1900
    ld hl,0xFAF5              /* -$050B: carry iff the SDK address is >= $050B */
    add hl,de
    jr nc,.rom_target_ready
    ld hl,0x001A
    add hl,de
    ex de,hl
.rom_target_ready:
.elseif BURN_ROM_PROFILE == 19006
    /*
     * ROM 19.006 moved the documented CrASH/SNG SDK entries in several blocks,
     * rather than by one global delta. Other pages and low calls stay direct;
     * only documented SDK entries in the translated pages are guaranteed.
     */
    ld hl,.rom_ranges_37
    ld a,d
    sub 0x21
    cp 2
    jr c,.rom_find_range       /* Pre-19 $21xx/$22xx use the +$0145 range. */
    jr z,.rom_add_012b         /* ROM 19.0 $23xx entries moved by $012B. */
    cp 4
    jr z,.rom_find_range       /* Pre-19 $25xx uses the +$0145 range. */
    sub 0x15
    jr nz,.rom_page_ready_19006
    ld a,e
    cp 0x06
    jr nz,.rom_target_ready_19006
    jr .rom_find_range         /* Only pre-19 $3606 uses the +$0145 range. */
.rom_page_ready_19006:
    dec a
    jr z,.rom_find_range
    ld l,.rom_ranges_38-burn_start+0x4E
    dec a
    jr z,.rom_find_range
    ld l,.rom_ranges_39-burn_start+0x4E
    dec a
    jr nz,.rom_target_ready_19006
.rom_find_range:
    ld a,e
    cp (hl)
    inc hl
    jr nc,.rom_range_found
    inc hl
    jr .rom_find_range
.rom_range_found:
    ld l,(hl)
    ld a,l
    rlca
    and 1
    inc a
    ld h,a
    jr .rom_add_delta
.rom_add_012b:
    ld hl,0x012B
.rom_add_delta:
    add hl,de
    ex de,hl
.rom_target_ready_19006:
.else
    /* CrASH's documented ROM_CALL operands are native on ROMs 15.0..18.0. */
    .space 11,0               /* Keep all non-public shell labels aligned with 19.0. */
.endif
    push de
    exx
    ex af,af'
    ret

.if BURN_ROM_PROFILE == 19006
/* Descending low-byte thresholds and 16-bit delta low bytes.  Bit 7 marks the
   sole $0295 delta; unmarked entries have a high delta byte of one. */
.rom_ranges_37:
    .byte 0xC8,0x39, 0xB0,0x95, 0x00,0x45
.rom_ranges_38:
    .byte 0xFA,0x33, 0xDC,0x2D, 0xD0,0x33, 0xCA,0x27, 0x7C,0x33, 0x00,0x39
.rom_ranges_39:
    .byte 0x24,0x63, 0x00,0x57

/* Scan exactly the still-unconsumed Ash body bytes supplied by the bounded
   comment parser.  Like SNG's compatibility loader this is a linear byte
   scan, so data may look like an opcode, but operand reads never cross the
   allocation: fewer than three bytes means no complete CALL remains. */
.ash_patch_check:
    jr nz,.ash_scan_byte
    ld a,c
    cp 3
    ret c
.ash_scan_byte:
    ld a,(hl)
    inc hl
    dec bc
    cp 0xCD
    jr nz,.ash_continue
.ash_call_operand:
    inc hl
    ld a,(hl)
    dec hl
    dec a
    jr z,.ash_page_01
    sub 6
    jr nz,.ash_continue
    ld a,(hl)
    cp 0xF3
    jr nz,.ash_continue
    ld (hl),0x3A
    inc hl
    inc (hl)
    dec hl
    jr .ash_continue
.ash_page_01:
    ld a,(hl)
    sub 0xB8
    jr z,.ash_add_1f
    sub 0x0F
    jr z,.ash_add_1f
    sub 0x0D
    jr nz,.ash_continue
.ash_add_1f:
    ld a,(hl)
    add a,0x1F
    ld (hl),a
.ash_continue:
    jp classic_patch_calls
.endif

shell_main:
    call ROM_RUN_INDIC_OFF
    di

    /* Stock CrASH has four unused tail bytes; remove them once to own $8D24..$90FE. */
    ld hl,(ANCHOR_LEN_WORD)
    ld de,ANCHOR_FINAL_LEN
    or a
    sbc hl,de
    jr z,.anchor_ready
    ld a,l
    sub ANCHOR_OLD_LEN-ANCHOR_FINAL_LEN
    or h
    jp nz,shell_fail
    ld hl,TARGET_BASE
    ld de,ANCHOR_OLD_LEN-ANCHOR_FINAL_LEN
    call ROM_DEL_MEM
    ld hl,ANCHOR_FINAL_LEN
    ld (ANCHOR_LEN_WORD),hl

.anchor_ready:
    ei
    xor a
    ld (selected_index),a

menu_refresh:
    ld b,0
.count_loop:
    ld a,b
    push bc
    call find_nth_compatible
    pop bc
    jr nc,.count_done
    inc b
    jr nz,.count_loop
    dec b                       /* Saturate the byte-sized catalog at 255. */
.count_done:
    ld a,b
    ld (program_count),a
    or a
    jp z,shell_exit
    ld a,(selected_index)
    cp b
    jr c,.selection_valid
    xor a
    ld (selected_index),a
.selection_valid:
    call draw_menu

menu_key_loop:
    /* The ROM interrupt handler advances its APD timers only while this bit is set. */
    res apdAble,(iy+apdFlags)
.release:
    ei
menu_release_idle_halt:
    halt
    call ROM_GET_CSC
    or a
    jr nz,.release
.press:
    ei
menu_idle_halt:
    halt
menu_idle_wake:
    call ROM_GET_CSC
    or a
    jr z,.press
    /* Targets and TI-OS must inherit the normal APD-enabled state. */
    set apdAble,(iy+apdFlags)
    cp KEY_CLEAR
    jp z,shell_exit
    cp KEY_MODE
    jp z,shell_exit
    cp KEY_ENTER
    jp z,launch_selected
    ld hl,selected_index
    cp KEY_DOWN
    jr z,.down
    cp KEY_UP
    jr z,.up
.if BURN_ROM_PROFILE == 19006
    jr menu_key_loop            /* Up/Down retain access to every catalog entry. */
.else
    cp KEY_RIGHT
    jr z,.page_down
    cp KEY_LEFT
    jr nz,menu_key_loop
    ld a,(hl)
    sub PAGE_ROWS
    jr c,menu_key_loop
    ld (hl),a
    jr .redraw
.page_down:
    ld a,(hl)
    add a,PAGE_ROWS
    jr c,menu_key_loop
    inc hl
    cp (hl)
    jr nc,menu_key_loop
    dec hl
    ld (hl),a
    jr .redraw
.endif
.redraw:
    jr menu_refresh
.down:
    inc hl
    ld a,(hl)
    dec hl
    dec a
    cp (hl)
    jr z,menu_key_loop
    inc (hl)
    jr .redraw
.up:
    ld a,(hl)
    or a
    jr z,menu_key_loop
    dec (hl)
    jr .redraw

draw_menu:
    res appTextSave,(iy+appFlags)
    res textWrite,(iy+sGrFlags)
    res textInverse,(iy+textFlags) /* Always render black on white. */
    call ROM_CLR_LCD_FULL
    ld hl,0
    ld (curRow),hl

    /* The selected entry starts the six-entry viewport. */
    ld a,(selected_index)
    ld (display_index),a

.draw_row:
    ld a,(curRow)
    cp PAGE_ROWS
    ret nc
    ld a,(display_index)
    ld hl,program_count
    cp (hl)
    ret nc
    call find_nth_compatible
    ret nc
    push hl                     /* Finder returns the VAT header in HL. */
    push af                     /* Candidate kind returned by the finder. */

    xor a
    ld (curCol),a
    ld a,(curRow)
    or a
    ld a,'>'
    jr z,.selection_mark
    ld a,' '
.selection_mark:
    call ROM_PUT_C

    pop af
    pop hl
    or a
    jr nz,.classic_comment

    dec hl
    dec hl
    dec hl
    ld b,(hl)
    dec hl
.name_loop:
    ld a,(hl)
    call ROM_PUT_C
    dec hl
    djnz .name_loop
    jr .display_done

.classic_comment:
    ex de,hl                    /* Finder returns the allocation in DE. */
    ld de,5
    add hl,de                    /* Bounded user RAM keeps carry clear. */
    ld b,14
.comment_loop:
    ld a,(hl)
    inc hl
    or a
    jr z,.display_done
    call ROM_PUT_C
    djnz .comment_loop
    ld a,(hl)
    or a
    jr z,.display_done          /* Exactly 14 characters needs no ellipsis. */
    ld a,0xCE                   /* Lellipsis */
    call ROM_PUT_C
    jr .display_next            /* A full line already advanced the OS cursor. */
.display_done:
    ld hl,curRow
    inc (hl)
.display_next:
    ld hl,display_index
    inc (hl)
    jr .draw_row

/*
 * Find compatible program A in descending-VAT order.  Carry is set on success;
 * HL returns its VAT type-byte address, DE its allocation pointer, and A
 * returns 0 raw, 1 for a byte-zero classic header, and 2 for any nonzero
 * classic RAM-policy byte.
 */
find_nth_compatible:
    ld c,a
    ld hl,symTable
.scan_entry:
    ld de,(pTemp)
.if BURN_ROM_PROFILE == 19006
    or a
    sbc hl,de
    jr z,.not_found
    add hl,de
.else
    push hl
    or a
    sbc hl,de
    jr c,.header_gap_bad
    ld a,h
    or a
    jr nz,.header_gap_ok
    ld a,l
    cp 5
    jr nc,.header_gap_ok
.header_gap_bad:
    pop hl
    jr .not_found
.header_gap_ok:
    pop hl
.endif
    ld a,(hl)
    and 0x0F
    cp 0x05
    jr z,.program_type
    cp 0x06
    jr nz,.next_entry
.program_type:

    push hl
    dec hl
    ld e,(hl)
    dec hl
    ld d,(hl)
.if BURN_ROM_PROFILE == 19006
    push de
.endif
    push bc
    call classify_candidate
    pop bc
.if BURN_ROM_PROFILE == 19006
    pop de
.endif
    pop hl
    jr nc,.next_entry
    ld b,a
    ld a,c
    or a
    jr z,.found
    dec c

.next_entry:
    call previous_vat_header
.if BURN_ROM_PROFILE != 19006
    jr nc,.not_found
.endif
    jr .scan_entry

.found:
.if BURN_ROM_PROFILE != 19006
    dec hl
    ld e,(hl)
    dec hl
    ld d,(hl)
    inc hl
    inc hl
.endif
    ld a,b
    scf
    ret
.not_found:
    or a
    ret

/* Return the previous variable's type-byte address from the current one in HL. */
previous_vat_header:
    ld a,(hl)
    and 0x0F
    cp 0x05
    jr z,.long_name
    cp 0x06
    jr z,.long_name
    cp 0x09
    jr z,.long_name
    ld de,-6
    add hl,de
.if BURN_ROM_PROFILE == 19006
    ret
.else
    jr .validate_previous
.endif
.long_name:
    dec hl
    dec hl
    dec hl
    ld e,(hl)
    ld d,0
    dec hl
    sbc hl,de
.if BURN_ROM_PROFILE == 19006
    ret
.else
.validate_previous:
    ld de,(pTemp)
    push hl
    or a
    sbc hl,de
    pop hl
    jr c,.bad_previous
    scf
    ret
.bad_previous:
    or a
    ret
.endif

/* Validate marker, bounded NUL, and at least one target body byte. */
classify_candidate:
    ex de,hl
.if BURN_ROM_PROFILE != 19006
    push hl
    ld de,TARGET_BASE
    or a
    sbc hl,de
    pop hl
    jr c,.invalid
.endif
    ld c,(hl)
    inc hl
    ld b,(hl)
    inc hl
    push hl
    ld de,(FPS)
    ex de,hl
    or a
    sbc hl,de
    jr c,.invalid_pop
    sbc hl,bc
    pop hl
    jr c,.invalid
    ld a,b
    or a
    jr nz,.minimum_size_ok
    ld a,c
    cp 4
    jr c,.invalid
.minimum_size_ok:
    ld a,(hl)
    inc hl
    cp 0xFE
    jr nz,.try_crash
    ld a,(hl)
    inc hl
    cp 0x82
    jr nz,.invalid
    ld a,(hl)
    sub 0x0F
    jr nz,.invalid
                                /* raw FE 82 0F leaves A=0 */
    scf
    ret

.try_crash:
    ld d,0x11
    cp 0xD5
    jr z,.classic_marker
    ld d,0x30
    cp 0xD9
    jr nz,.invalid
.classic_marker:
    ld e,(hl)
    inc hl
    ld a,(hl)
    inc hl
    cp d
    jr nz,.invalid
    dec bc
    dec bc
    dec bc
.scan_comment:
    xor a
    cpir
    ret po                     /* Reject missing/final NUL with carry still clear. */
.if BURN_ROM_PROFILE == 19006
    call classic_patch_calls
.endif
    xor a
    cp e
    adc a,1
    scf
    ret
.invalid_pop:
    pop hl
.invalid:
    or a
    ret

launch_selected:
    ld a,(selected_index)
    call find_nth_compatible
    jp nc,shell_fail
    /* Raw and byte-nonzero classic programs request BuRN's free-RAM launch.
       A byte-zero classic header retains the valid CrASH program-edit context. */
    dec a
.if BURN_ROM_PROFILE == 19006
    jr nz,.close_target_edit

    /* Keep the real edit context for zero-policy programs and reverse BuRN's
       overlapping exchange before returning control to TI-OS. */
    push hl                     /* Stable VAT header below length and policy. */
    ld hl,(OPS)
    inc hl
    ld (FPBase),hl
    ld (FPS),hl
    ld hl,(TARGET_BASE)
    ld a,h
    or l
    jp nz,shell_fail            /* Another relocated target owns the execution buffer. */
    ex de,hl                    /* HL=selected allocation. */
    ld c,(hl)
    inc hl
    ld b,(hl)
    inc hl
    push bc                     /* Retain the body length below the launch policy. */
    push af
    call swap_edit_target
    jr .target_positioned
.else
    jr nz,.close_target_edit

    /* Stock CrASH leaves no allocator gap while the edit context is open. */
    push hl                     /* Keep the stable VAT header below length and policy. */
    ld hl,(OPS)
    inc hl
    ld (FPBase),hl
    ld (FPS),hl
    ld hl,(TARGET_BASE)
    ld a,h
    or l
    jp nz,shell_fail            /* Another relocated target owns the execution buffer. */
.target_buffer_free:
    push af                     /* Zero encodes the occupied-context return path. */
    ex de,hl                    /* HL=selected allocation. */
    ld c,(hl)
    inc hl
    ld b,(hl)
    inc hl
    pop af
    push bc                     /* Retain the body length below the launch policy. */
    push af
    call swap_edit_target
    jr .target_positioned
.endif
.close_target_edit:
    push af                     /* $FF raw, 1 for a byte-nonzero classic header. */
.if BURN_ROM_PROFILE != 19006
    push hl
.endif
    call ROM_CLOSE_EDIT
    /* Closing the edit context changes RAM geometry; reload the selected
       allocation pointer from its VAT header.  On 19.006, re-find the selected
       entry instead of assuming the pre-close header/pointer pair is current. */
.if BURN_ROM_PROFILE == 19006
    ld a,(selected_index)
    call find_nth_compatible
.else
    pop hl
    dec hl
    ld e,(hl)
    dec hl
    ld d,(hl)
.endif
.if BURN_ROM_PROFILE == 19006
    dec hl                      /* Point at the selected VAT data pointer. */
    dec hl
    push hl                     /* Keep it below the mover's remaining length. */
.endif
.target_edit_ready:
    di

    ex de,hl                    /* HL=allocation, DE=VAT pointer-high byte. */
    ld bc,TARGET_BASE
    or a
    sbc hl,bc
    /* find_nth_compatible already proved source_ptr >= TARGET_BASE. */
.if BURN_ROM_PROFILE == 19006
    jr z,.move_done             /* Pop and normalize the saved VAT pointer. */
.else
    jr z,.target_positioned
    push de                     /* Header moves only when the allocation moves. */
.endif
    add hl,bc

    /* Move from the allocation's fixed end towards its length word.  Deleting
       the current tail and inserting it at TARGET_BASE leaves that end address
       unchanged while prepending chunks in their original order. */
    ld c,(hl)
    inc hl
    ld b,(hl)
    inc hl
    add hl,bc
    ld (source_ptr),hl
    inc bc
    inc bc
    push bc

.move_loop:
    pop hl
    ld bc,MOVE_CHUNK
    or a
    sbc hl,bc
    jr nc,.chunk_ready
.partial_chunk:
    add hl,bc
    ld c,l
    ld b,h
    /* H is already zero because the remainder is smaller than MOVE_CHUNK. */
    ld l,b
.chunk_ready:
    push hl
    push bc
    ld hl,(source_ptr)
    or a
    sbc hl,bc
    push hl
    ld de,move_buffer
    ldir

    pop hl
    pop de
    push de
    call ROM_DEL_MEM

    pop hl
    push hl
    ld de,TARGET_BASE
    call ROM_INSERT_MEM

    pop bc
    push bc
    ld hl,move_buffer
    ld de,TARGET_BASE
    ldir
    pop bc

    pop hl
    ld a,h
    or l
    jr z,.move_done
    push hl
    jr .move_loop

.move_done:
    ld (move_buffer),a
    /* Program VAT pointers are high byte then low byte immediately below type. */
    pop hl
    ld (hl),0x90
    inc hl
    ld (hl),0xFF

.target_positioned:
.if BURN_ROM_PROFILE == 19006
    ld hl,RAW_ENTRY
    ld a,(TARGET_CONTENT)
    sub 0xFE
    jr z,.launch
.else
    ld hl,TARGET_CONTENT
    ld a,(TARGET_CONTENT)
    sub 0xFE
    jr nz,.crash_entry
    ld hl,RAW_ENTRY
    jr .launch
.endif

.crash_entry:
.if BURN_ROM_PROFILE != 19006
    ld hl,RAW_ENTRY
.endif
    ld bc,(TARGET_BASE)
    dec bc
    dec bc
    dec bc
    xor a
    cpir
.if BURN_ROM_PROFILE == 19006
    /* find_nth_compatible already proved that this bounded NUL exists. */
.else
    jp po,shell_fail           /* Require a NUL before the last body byte. */
.endif
    inc a                      /* Preserve the later classic-initializer NZ test. */

.launch:
    res textWrite,(iy+sGrFlags)
    ld de,.target_return
    push de
    push hl
    jr nz,classic_init

    /* Raw programs receive the same zeroed general-register handoff. */
zero_general_registers:
    xor a
    ld b,a
    ld c,a
zero_remaining_registers:
    ld d,a
    ld e,a
    ld h,a
    ld l,a
    push bc
    pop ix
    jr target_ready

classic_init_start:
classic_init:
    /* Keep all common SafeRAM intact.  In particular, textShadow becomes the
       home screen after exit and plotSScreen may contain live graph state.
       Preserve the useful, non-SafeRAM part of the classic launch contract:
       zero cursors and the documented general registers. */
    xor a
    ld b,a
    ld c,a
    ld (curRow),bc
    ld (grafCurs),bc
    jr zero_remaining_registers
classic_init_end:
target_ready:
    ei
target_call:
    ret
.target_return:
    pop af
.if BURN_ROM_PROFILE == 19006
    /* The saved policy also preserves Z: set only for byte-zero headers. */
    jr z,.restore_and_close
    /* Free-RAM programs have no valid edit context.  They may nevertheless
       leave editOpen set, so clear the flag without calling _CloseEdit on
       unrelated edit pointers. */
    res editOpen,(iy+editFlags)
    jr shell_exit
.restore_and_close:
    pop bc
    pop hl
    call restore_edit_target
    /* Release the restored edit context before handing control to TI-OS. */
    call ROM_CLOSE_EDIT
shell_fail:
shell_exit:
    /* _ClrWindow homes the cursor and, with text saving enabled, also blanks
       the saved home screen. */
    set appTextSave,(iy+appFlags)
    call ROM_CLR_WINDOW
    call ROM_RUN_INDIC_ON
shell_exit_handoff:
    jp ROM_FORCE_CMD
.else
    inc a
    jr z,.menu_return
    dec a
    jr nz,.clear_and_exit
    pop bc
    pop hl
    call restore_edit_target
.menu_return:
    call ROM_RUN_INDIC_OFF
    jp menu_refresh
.endif

/* Swap BC bytes between an OS-owned program body at HL and $9101. */
swap_edit_target:
    ld de,TARGET_CONTENT
.swap_byte:
    ld a,(de)
    ldi
    dec hl
    ld (hl),a
    inc hl
    ret po
    jr .swap_byte

/* Reload a possibly moved allocation through its stable VAT header, restore
   its content length, then reverse the overlapping exchange. */
restore_edit_target:
    dec hl
    ld e,(hl)
    dec hl
    ld d,(hl)
    ex de,hl
    ld (hl),c
    inc hl
    ld (hl),b
    inc hl

/* Reverse direction is required on return because the two ranges overlap. */
swap_edit_target_back:
    ex de,hl
    ld hl,TARGET_CONTENT-1
    add hl,bc
    ex de,hl
    add hl,bc
.swap_byte_back:
    dec hl
    ld a,(de)
    ldd
    inc hl
    ld (hl),a
    ret po
    jr .swap_byte_back

.if BURN_ROM_PROFILE != 19006
.clear_and_exit:
    /* A free-RAM program may have consumed or reorganized that RAM. */
    res editOpen,(iy+editFlags)
    jr shell_exit
.endif

target_forced_exit:
    /* EXIT_2_TIOS is a CALL in the CrASH ABI.  Discard its return address and
       BuRN's target-return address, then restore a byte-zero classic program
       before leaving.  Raw/free-policy callers have no exchange to restore. */
    pop hl
    pop hl
.if BURN_ROM_PROFILE == 19006
    jr .target_return
.else
    pop af
    or a
    jr nz,shell_exit
.restore_and_exit:
    pop bc
    pop hl
    call restore_edit_target
    jr shell_exit
.endif

.if BURN_ROM_PROFILE != 19006
shell_fail:
shell_exit:
    /* Menu and restored zero-policy exits own a valid edit context.  Free-RAM
       exits clear editOpen first, making this a safe no-op for their unrelated
       edit pointers. */
    call ROM_CLOSE_EDIT
    /* _ClrWindow homes the cursor and, with text saving enabled, also blanks
       the saved home screen. */
    set appTextSave,(iy+appFlags)
    call ROM_CLR_WINDOW
    call ROM_RUN_INDIC_ON
shell_exit_handoff:
    jp ROM_FORCE_CMD
.endif

.if BURN_ROM_PROFILE == 19006
source_ptr:
selected_index:
    .byte 0
program_count:
    .byte 0
.else
selected_index:
    .byte 0
source_ptr:
    .word 0
.equ program_count, source_ptr
.endif
private_state_end:

.if (0x90FF - 0x8D4E - (. - burn_start)) > 0
.space 0x90FF - 0x8D4E - (. - burn_start), 0
.endif
burn_end:

.if (burn_end-burn_start) != (0x90FF-0x8D4E)
.error "BuRN body must end exactly at $90FF"
.endif
