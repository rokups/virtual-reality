/*
 * License agreement
 *
 * Hacker Disassembler Engine 32 C
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#if _WIN32
#   undef NOMINMAX
#   include <windows.h>
#   define MIN min
#   define MAX max
#elif __linux__
#   include <sys/param.h>
#   include <sys/mman.h>
#   include <unistd.h>
#   include <errno.h>
#   include <dlfcn.h>
#else
typedef char unsupported_platform[-1];
#endif
#if __amd64__ || _M_X64
#   define HOOKER_X64 1
#endif

#include "hooker.h"
#include <string.h>

#if __amd64__ || _M_X64

#pragma pack(push,1)

typedef struct {
    uint8_t len;
    uint8_t p_rep;
    uint8_t p_lock;
    uint8_t p_seg;
    uint8_t p_66;
    uint8_t p_67;
    uint8_t rex;
    uint8_t rex_w;
    uint8_t rex_r;
    uint8_t rex_x;
    uint8_t rex_b;
    uint8_t opcode;
    uint8_t opcode2;
    uint8_t modrm;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;
    union {
        uint8_t imm8;
        uint16_t imm16;
        uint32_t imm32;
        uint64_t imm64;
    } imm;
    union {
        uint8_t disp8;
        uint16_t disp16;
        uint32_t disp32;
    } disp;
    uint32_t flags;
} hde64s;

#define C_NONE    0x00
#define C_MODRM   0x01
#define C_IMM8    0x02
#define C_IMM16   0x04
#define C_IMM_P66 0x10
#define C_REL8    0x20
#define C_REL32   0x40
#define C_GROUP   0x80
#define C_ERROR   0xff

#define PRE_ANY  0x00
#define PRE_NONE 0x01
#define PRE_F2   0x02
#define PRE_F3   0x04
#define PRE_66   0x08
#define PRE_67   0x10
#define PRE_LOCK 0x20
#define PRE_SEG  0x40
#define PRE_ALL  0xff

#define DELTA_OPCODES      0x4a
#define DELTA_FPU_REG      0xfd
#define DELTA_FPU_MODRM    0x104
#define DELTA_PREFIXES     0x13c
#define DELTA_OP_LOCK_OK   0x1ae
#define DELTA_OP2_LOCK_OK  0x1c6
#define DELTA_OP_ONLY_MEM  0x1d8
#define DELTA_OP2_ONLY_MEM 0x1e7

unsigned char hde64_table[] = {
  0xa5,0xaa,0xa5,0xb8,0xa5,0xaa,0xa5,0xaa,0xa5,0xb8,0xa5,0xb8,0xa5,0xb8,0xa5,
  0xb8,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xac,0xc0,0xcc,0xc0,0xa1,0xa1,
  0xa1,0xa1,0xb1,0xa5,0xa5,0xa6,0xc0,0xc0,0xd7,0xda,0xe0,0xc0,0xe4,0xc0,0xea,
  0xea,0xe0,0xe0,0x98,0xc8,0xee,0xf1,0xa5,0xd3,0xa5,0xa5,0xa1,0xea,0x9e,0xc0,
  0xc0,0xc2,0xc0,0xe6,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0xab,
  0x8b,0x90,0x64,0x5b,0x5b,0x5b,0x5b,0x5b,0x92,0x5b,0x5b,0x76,0x90,0x92,0x92,
  0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x6a,0x73,0x90,
  0x5b,0x52,0x52,0x52,0x52,0x5b,0x5b,0x5b,0x5b,0x77,0x7c,0x77,0x85,0x5b,0x5b,
  0x70,0x5b,0x7a,0xaf,0x76,0x76,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,
  0x5b,0x5b,0x86,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xd5,0x03,0xcc,0x01,0xbc,
  0x03,0xf0,0x03,0x03,0x04,0x00,0x50,0x50,0x50,0x50,0xff,0x20,0x20,0x20,0x20,
  0x01,0x01,0x01,0x01,0xc4,0x02,0x10,0xff,0xff,0xff,0x01,0x00,0x03,0x11,0xff,
  0x03,0xc4,0xc6,0xc8,0x02,0x10,0x00,0xff,0xcc,0x01,0x01,0x01,0x00,0x00,0x00,
  0x00,0x01,0x01,0x03,0x01,0xff,0xff,0xc0,0xc2,0x10,0x11,0x02,0x03,0x01,0x01,
  0x01,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0x00,0x00,0xff,0xff,0xff,0xff,0x10,
  0x10,0x10,0x10,0x02,0x10,0x00,0x00,0xc6,0xc8,0x02,0x02,0x02,0x02,0x06,0x00,
  0x04,0x00,0x02,0xff,0x00,0xc0,0xc2,0x01,0x01,0x03,0x03,0x03,0xca,0x40,0x00,
  0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,0x00,0x00,0x00,
  0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0xff,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
  0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x00,0x00,
  0xff,0x40,0x40,0x40,0x40,0x41,0x49,0x40,0x40,0x40,0x40,0x4c,0x42,0x40,0x40,
  0x40,0x40,0x40,0x40,0x40,0x40,0x4f,0x44,0x53,0x40,0x40,0x40,0x44,0x57,0x43,
  0x5c,0x40,0x60,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
  0x40,0x40,0x64,0x66,0x6e,0x6b,0x40,0x40,0x6a,0x46,0x40,0x40,0x44,0x46,0x40,
  0x40,0x5b,0x44,0x40,0x40,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x01,0x06,
  0x06,0x02,0x06,0x06,0x00,0x06,0x00,0x0a,0x0a,0x00,0x00,0x00,0x02,0x07,0x07,
  0x06,0x02,0x0d,0x06,0x06,0x06,0x0e,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
  0x04,0x04,0x05,0x06,0x06,0x06,0x00,0x00,0x00,0x0e,0x00,0x00,0x08,0x00,0x10,
  0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,0x86,0x00,
  0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,0xf8,0xbb,
  0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,0xc4,0xff,
  0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,0x13,0x09,
  0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,0xb2,0xff,
  0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,0xe7,0x08,
  0x00,0xf0,0x02,0x00
};

#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_IMM64         0x00000020
#define F_DISP8         0x00000040
#define F_DISP16        0x00000080
#define F_DISP32        0x00000100
#define F_RELATIVE      0x00000200
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_REX    0x40000000
#define F_PREFIX_ANY    0x7f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    uint8_t x, c, *p = (uint8_t*)code, cflags, opcode, pref = 0;
    uint8_t *ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
    uint8_t op64 = 0;

    memset(hs,0,sizeof(hde64s));

    for (x = 16; x; x--)
        switch (c = *p++) {
        case 0xf3:
            hs->p_rep = c;
            pref |= PRE_F3;
            break;
        case 0xf2:
            hs->p_rep = c;
            pref |= PRE_F2;
            break;
        case 0xf0:
            hs->p_lock = c;
            pref |= PRE_LOCK;
            break;
        case 0x26: case 0x2e: case 0x36:
        case 0x3e: case 0x64: case 0x65:
            hs->p_seg = c;
            pref |= PRE_SEG;
            break;
        case 0x66:
            hs->p_66 = c;
            pref |= PRE_66;
            break;
        case 0x67:
            hs->p_67 = c;
            pref |= PRE_67;
            break;
        default:
            goto pref_done;
    }
pref_done:

    hs->flags = (uint32_t)pref << 23;

    if (!pref)
        pref |= PRE_NONE;

    if ((c & 0xf0) == 0x40) {
        hs->flags |= F_PREFIX_REX;
        if ((hs->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
            op64++;
        hs->rex_r = (c & 7) >> 2;
        hs->rex_x = (c & 3) >> 1;
        hs->rex_b = c & 1;
        if (((c = *p++) & 0xf0) == 0x40) {
            opcode = c;
            goto error_opcode;
        }
    }

    if ((hs->opcode = c) == 0x0f) {
        hs->opcode2 = c = *p++;
        ht += DELTA_OPCODES;
    } else if (c >= 0xa0 && c <= 0xa3) {
        op64++;
        if (pref & PRE_67)
            pref |= PRE_66;
        else
            pref &= ~PRE_66;
    }

    opcode = c;
    cflags = ht[ht[opcode / 4] + (opcode % 4)];

    if (cflags == C_ERROR) {
error_opcode:
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if ((opcode & -3) == 0x24)
            cflags++;
    }

    x = 0;
    if (cflags & C_GROUP) {
        uint16_t t;
        t = *(uint16_t*)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    if (hs->opcode2) {
        ht = hde64_table + DELTA_PREFIXES;
        if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    if (cflags & C_MODRM) {
        hs->flags |= F_MODRM;
        hs->modrm = c = *p++;
        hs->modrm_mod = m_mod = c >> 6;
        hs->modrm_rm = m_rm = c & 7;
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
            uint8_t t = opcode - 0xd9;
            if (m_mod == 3) {
                ht = hde64_table + DELTA_FPU_MODRM + t*8;
                t = ht[m_reg] << m_rm;
            } else {
                ht = hde64_table + DELTA_FPU_REG;
                t = ht[t] << m_reg;
            }
            if (t & 0x80)
                hs->flags |= F_ERROR | F_ERROR_OPCODE;
        }

        if (pref & PRE_LOCK) {
            if (m_mod == 3) {
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                uint8_t* table_end, op = opcode;
                if (hs->opcode2) {
                    ht = hde64_table + DELTA_OP2_LOCK_OK;
                    table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
                } else {
                    ht = hde64_table + DELTA_OP_LOCK_OK;
                    table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
                    op &= -2;
                }
                for (; ht != table_end; ht++)
                    if (*ht++ == op) {
                        if (!((*ht << m_reg) & 0x80))
                            goto no_lock_error;
                        else
                            break;
                    }
                    hs->flags |= F_ERROR | F_ERROR_LOCK;
no_lock_error:
                    ;
            }
        }

        if (hs->opcode2) {
            switch (opcode) {
            case 0x20: case 0x22:
                m_mod = 3;
                if (m_reg > 4 || m_reg == 1)
                    goto error_operand;
                else
                    goto no_error_operand;
            case 0x21: case 0x23:
                m_mod = 3;
                if (m_reg == 4 || m_reg == 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            }
        } else {
            switch (opcode) {
            case 0x8c:
                if (m_reg > 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            case 0x8e:
                if (m_reg == 1 || m_reg > 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            }
        }

        if (m_mod == 3) {
            uint8_t* table_end;
            if (hs->opcode2) {
                ht = hde64_table + DELTA_OP2_ONLY_MEM;
                table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
            } else {
                ht = hde64_table + DELTA_OP_ONLY_MEM;
                table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
            }
            for (; ht != table_end; ht += 2)
                if (*ht++ == opcode) {
                    if (*ht++ & pref && !((*ht << m_reg) & 0x80))
                        goto error_operand;
                    else
                        break;
                }
                goto no_error_operand;
        } else if (hs->opcode2) {
            switch (opcode) {
            case 0x50: case 0xd7: case 0xf7:
                if (pref & (PRE_NONE | PRE_66))
                    goto error_operand;
                break;
            case 0xd6:
                if (pref & (PRE_F2 | PRE_F3))
                    goto error_operand;
                break;
            case 0xc5:
                goto error_operand;
            }
            goto no_error_operand;
        } else
            goto no_error_operand;

error_operand:
        hs->flags |= F_ERROR | F_ERROR_OPERAND;
no_error_operand:

        c = *p++;
        if (m_reg <= 1) {
            if (opcode == 0xf6)
                cflags |= C_IMM8;
            else if (opcode == 0xf7)
                cflags |= C_IMM_P66;
        }

        switch (m_mod) {
        case 0:
            if (pref & PRE_67) {
                if (m_rm == 6)
                    disp_size = 2;
            } else
                if (m_rm == 5)
                    disp_size = 4;
            break;
        case 1:
            disp_size = 1;
            break;
        case 2:
            disp_size = 2;
            if (!(pref & PRE_67))
                disp_size <<= 1;
        }

        if (m_mod != 3 && m_rm == 4) {
            hs->flags |= F_SIB;
            p++;
            hs->sib = c;
            hs->sib_scale = c >> 6;
            hs->sib_index = (c & 0x3f) >> 3;
            if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                disp_size = 4;
        }

        p--;
        switch (disp_size) {
        case 1:
            hs->flags |= F_DISP8;
            hs->disp.disp8 = *p;
            break;
        case 2:
            hs->flags |= F_DISP16;
            hs->disp.disp16 = *(uint16_t*)p;
            break;
        case 4:
            hs->flags |= F_DISP32;
            hs->disp.disp32 = *(uint32_t*)p;
        }
        p += disp_size;
    } else if (pref & PRE_LOCK)
        hs->flags |= F_ERROR | F_ERROR_LOCK;

    if (cflags & C_IMM_P66) {
        if (cflags & C_REL32) {
            if (pref & PRE_66) {
                hs->flags |= F_IMM16 | F_RELATIVE;
                hs->imm.imm16 = *(uint16_t*)p;
                p += 2;
                goto disasm_done;
            }
            goto rel32_ok;
        }
        if (op64) {
            hs->flags |= F_IMM64;
            hs->imm.imm64 = *(uint64_t*)p;
            p += 8;
        } else if (!(pref & PRE_66)) {
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t*)p;
            p += 4;
        } else
            goto imm16_ok;
    }


    if (cflags & C_IMM16) {
imm16_ok:
        hs->flags |= F_IMM16;
        hs->imm.imm16 = *(uint16_t*)p;
        p += 2;
    }
    if (cflags & C_IMM8) {
        hs->flags |= F_IMM8;
        hs->imm.imm8 = *p++;
    }

    if (cflags & C_REL32) {
rel32_ok:
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t*)p;
        p += 4;
    } else if (cflags & C_REL8) {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
    }

disasm_done:

    if ((hs->len = (uint8_t)(p-(uint8_t*)code)) > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        hs->len = 15;
    }

    return (unsigned int)hs->len;
}

#elif __i386__ || _M_IX86

#pragma pack(push,1)

typedef struct {
    uint8_t len;
    uint8_t p_rep;
    uint8_t p_lock;
    uint8_t p_seg;
    uint8_t p_66;
    uint8_t p_67;
    uint8_t opcode;
    uint8_t opcode2;
    uint8_t modrm;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;
    union {
        uint8_t imm8;
        uint16_t imm16;
        uint32_t imm32;
    } imm;
    union {
        uint8_t disp8;
        uint16_t disp16;
        uint32_t disp32;
    } disp;
    uint32_t flags;
} hde32s;

#pragma pack(pop)

#define C_NONE    0x00
#define C_MODRM   0x01
#define C_IMM8    0x02
#define C_IMM16   0x04
#define C_IMM_P66 0x10
#define C_REL8    0x20
#define C_REL32   0x40
#define C_GROUP   0x80
#define C_ERROR   0xff

#define PRE_ANY  0x00
#define PRE_NONE 0x01
#define PRE_F2   0x02
#define PRE_F3   0x04
#define PRE_66   0x08
#define PRE_67   0x10
#define PRE_LOCK 0x20
#define PRE_SEG  0x40
#define PRE_ALL  0xff

#define DELTA_OPCODES      0x4a
#define DELTA_FPU_REG      0xf1
#define DELTA_FPU_MODRM    0xf8
#define DELTA_PREFIXES     0x130
#define DELTA_OP_LOCK_OK   0x1a1
#define DELTA_OP2_LOCK_OK  0x1b9
#define DELTA_OP_ONLY_MEM  0x1cb
#define DELTA_OP2_ONLY_MEM 0x1da

unsigned char hde32_table[] = {
  0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,
  0xa8,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xac,0xaa,0xb2,0xaa,0x9f,0x9f,
  0x9f,0x9f,0xb5,0xa3,0xa3,0xa4,0xaa,0xaa,0xba,0xaa,0x96,0xaa,0xa8,0xaa,0xc3,
  0xc3,0x96,0x96,0xb7,0xae,0xd6,0xbd,0xa3,0xc5,0xa3,0xa3,0x9f,0xc3,0x9c,0xaa,
  0xaa,0xac,0xaa,0xbf,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0x90,
  0x82,0x7d,0x97,0x59,0x59,0x59,0x59,0x59,0x7f,0x59,0x59,0x60,0x7d,0x7f,0x7f,
  0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x9a,0x88,0x7d,
  0x59,0x50,0x50,0x50,0x50,0x59,0x59,0x59,0x59,0x61,0x94,0x61,0x9e,0x59,0x59,
  0x85,0x59,0x92,0xa3,0x60,0x60,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,
  0x59,0x59,0x9f,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xcc,0x01,0xbc,0x03,0xf0,
  0x10,0x10,0x10,0x10,0x50,0x50,0x50,0x50,0x14,0x20,0x20,0x20,0x20,0x01,0x01,
  0x01,0x01,0xc4,0x02,0x10,0x00,0x00,0x00,0x00,0x01,0x01,0xc0,0xc2,0x10,0x11,
  0x02,0x03,0x11,0x03,0x03,0x04,0x00,0x00,0x14,0x00,0x02,0x00,0x00,0xc6,0xc8,
  0x02,0x02,0x02,0x02,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0xca,
  0x01,0x01,0x01,0x00,0x06,0x00,0x04,0x00,0xc0,0xc2,0x01,0x01,0x03,0x01,0xff,
  0xff,0x01,0x00,0x03,0xc4,0xc4,0xc6,0x03,0x01,0x01,0x01,0xff,0x03,0x03,0x03,
  0xc8,0x40,0x00,0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,
  0x00,0x00,0x00,0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,
  0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0xff,0xff,0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x7f,0x00,0x00,0xff,0x4a,0x4a,0x4a,0x4a,0x4b,0x52,0x4a,0x4a,0x4a,0x4a,0x4f,
  0x4c,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x55,0x45,0x40,0x4a,0x4a,0x4a,
  0x45,0x59,0x4d,0x46,0x4a,0x5d,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,
  0x4a,0x4a,0x4a,0x4a,0x4a,0x61,0x63,0x67,0x4e,0x4a,0x4a,0x6b,0x6d,0x4a,0x4a,
  0x45,0x6d,0x4a,0x4a,0x44,0x45,0x4a,0x4a,0x00,0x00,0x00,0x02,0x0d,0x06,0x06,
  0x06,0x06,0x0e,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x00,0x06,0x06,0x02,0x06,
  0x00,0x0a,0x0a,0x07,0x07,0x06,0x02,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
  0x04,0x04,0x00,0x00,0x00,0x0e,0x05,0x06,0x06,0x06,0x01,0x06,0x00,0x00,0x08,
  0x00,0x10,0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,
  0x86,0x00,0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,
  0xf8,0xbb,0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,
  0xc4,0xff,0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,
  0x13,0x09,0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,
  0xb2,0xff,0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,
  0xe7,0x08,0x00,0xf0,0x02,0x00
};

#ifdef _MSC_VER
#pragma warning(disable:4701)
#endif

#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_DISP8         0x00000020
#define F_DISP16        0x00000040
#define F_DISP32        0x00000080
#define F_RELATIVE      0x00000100
#define F_2IMM16        0x00000800
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_ANY    0x3f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

unsigned int hde32_disasm(const void *code, hde32s *hs)
{
    uint8_t x, c, *p = (uint8_t*)code, cflags, opcode, pref = 0;
    uint8_t* ht = hde32_table, m_mod, m_reg, m_rm, disp_size = 0;

    memset(hs,0,sizeof(hde32s));

    for (x = 16; x; x--)
        switch (c = *p++) {
        case 0xf3:
            hs->p_rep = c;
            pref |= PRE_F3;
            break;
        case 0xf2:
            hs->p_rep = c;
            pref |= PRE_F2;
            break;
        case 0xf0:
            hs->p_lock = c;
            pref |= PRE_LOCK;
            break;
        case 0x26: case 0x2e: case 0x36:
        case 0x3e: case 0x64: case 0x65:
            hs->p_seg = c;
            pref |= PRE_SEG;
            break;
        case 0x66:
            hs->p_66 = c;
            pref |= PRE_66;
            break;
        case 0x67:
            hs->p_67 = c;
            pref |= PRE_67;
            break;
        default:
            goto pref_done;
    }
pref_done:

    hs->flags = (uint32_t)pref << 23;

    if (!pref)
        pref |= PRE_NONE;

    if ((hs->opcode = c) == 0x0f) {
        hs->opcode2 = c = *p++;
        ht += DELTA_OPCODES;
    } else if (c >= 0xa0 && c <= 0xa3) {
        if (pref & PRE_67)
            pref |= PRE_66;
        else
            pref &= ~PRE_66;
    }

    opcode = c;
    cflags = ht[ht[opcode / 4] + (opcode % 4)];

    if (cflags == C_ERROR) {
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if ((opcode & -3) == 0x24)
            cflags++;
    }

    x = 0;
    if (cflags & C_GROUP) {
        uint16_t t;
        t = *(uint16_t*)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    if (hs->opcode2) {
        ht = hde32_table + DELTA_PREFIXES;
        if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    if (cflags & C_MODRM) {
        hs->flags |= F_MODRM;
        hs->modrm = c = *p++;
        hs->modrm_mod = m_mod = c >> 6;
        hs->modrm_rm = m_rm = c & 7;
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
            uint8_t t = opcode - 0xd9;
            if (m_mod == 3) {
                ht = hde32_table + DELTA_FPU_MODRM + t*8;
                t = ht[m_reg] << m_rm;
            } else {
                ht = hde32_table + DELTA_FPU_REG;
                t = ht[t] << m_reg;
            }
            if (t & 0x80)
                hs->flags |= F_ERROR | F_ERROR_OPCODE;
        }

        if (pref & PRE_LOCK) {
            if (m_mod == 3) {
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                uint8_t* table_end, op = opcode;
                if (hs->opcode2) {
                    ht = hde32_table + DELTA_OP2_LOCK_OK;
                    table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
                } else {
                    ht = hde32_table + DELTA_OP_LOCK_OK;
                    table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
                    op &= -2;
                }
                for (; ht != table_end; ht++)
                    if (*ht++ == op) {
                        if (!((*ht << m_reg) & 0x80))
                            goto no_lock_error;
                        else
                            break;
                    }
                    hs->flags |= F_ERROR | F_ERROR_LOCK;
no_lock_error:
                    ;
            }
        }

        if (hs->opcode2) {
            switch (opcode) {
            case 0x20: case 0x22:
                m_mod = 3;
                if (m_reg > 4 || m_reg == 1)
                    goto error_operand;
                else
                    goto no_error_operand;
            case 0x21: case 0x23:
                m_mod = 3;
                if (m_reg == 4 || m_reg == 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            }
        } else {
            switch (opcode) {
            case 0x8c:
                if (m_reg > 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            case 0x8e:
                if (m_reg == 1 || m_reg > 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            }
        }

        if (m_mod == 3) {
            uint8_t* table_end;
            if (hs->opcode2) {
                ht = hde32_table + DELTA_OP2_ONLY_MEM;
                table_end = ht + sizeof(hde32_table) - DELTA_OP2_ONLY_MEM;
            } else {
                ht = hde32_table + DELTA_OP_ONLY_MEM;
                table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
            }
            for (; ht != table_end; ht += 2)
                if (*ht++ == opcode) {
                    if ((*ht++ & pref) && !((*ht << m_reg) & 0x80))
                        goto error_operand;
                    else
                        break;
                }
                goto no_error_operand;
        } else if (hs->opcode2) {
            switch (opcode) {
            case 0x50: case 0xd7: case 0xf7:
                if (pref & (PRE_NONE | PRE_66))
                    goto error_operand;
                break;
            case 0xd6:
                if (pref & (PRE_F2 | PRE_F3))
                    goto error_operand;
                break;
            case 0xc5:
                goto error_operand;
            }
            goto no_error_operand;
        } else
            goto no_error_operand;

error_operand:
        hs->flags |= F_ERROR | F_ERROR_OPERAND;
no_error_operand:

        c = *p++;
        if (m_reg <= 1) {
            if (opcode == 0xf6)
                cflags |= C_IMM8;
            else if (opcode == 0xf7)
                cflags |= C_IMM_P66;
        }

        switch (m_mod) {
        case 0:
            if (pref & PRE_67) {
                if (m_rm == 6)
                    disp_size = 2;
            } else
                if (m_rm == 5)
                    disp_size = 4;
            break;
        case 1:
            disp_size = 1;
            break;
        case 2:
            disp_size = 2;
            if (!(pref & PRE_67))
                disp_size <<= 1;
            break;
        }

        if (m_mod != 3 && m_rm == 4 && !(pref & PRE_67)) {
            hs->flags |= F_SIB;
            p++;
            hs->sib = c;
            hs->sib_scale = c >> 6;
            hs->sib_index = (c & 0x3f) >> 3;
            if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                disp_size = 4;
        }

        p--;
        switch (disp_size) {
        case 1:
            hs->flags |= F_DISP8;
            hs->disp.disp8 = *p;
            break;
        case 2:
            hs->flags |= F_DISP16;
            hs->disp.disp16 = *(uint16_t*)p;
            break;
        case 4:
            hs->flags |= F_DISP32;
            hs->disp.disp32 = *(uint32_t*)p;
            break;
        }
        p += disp_size;
    } else if (pref & PRE_LOCK)
        hs->flags |= F_ERROR | F_ERROR_LOCK;

    if (cflags & C_IMM_P66) {
        if (cflags & C_REL32) {
            if (pref & PRE_66) {
                hs->flags |= F_IMM16 | F_RELATIVE;
                hs->imm.imm16 = *(uint16_t*)p;
                p += 2;
                goto disasm_done;
            }
            goto rel32_ok;
        }
        if (pref & PRE_66) {
            hs->flags |= F_IMM16;
            hs->imm.imm16 = *(uint16_t*)p;
            p += 2;
        } else {
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t*)p;
            p += 4;
        }
    }

    if (cflags & C_IMM16) {
        if (hs->flags & F_IMM32) {
            hs->flags |= F_IMM16;
            hs->disp.disp16 = *(uint16_t*)p;
        } else if (hs->flags & F_IMM16) {
            hs->flags |= F_2IMM16;
            hs->disp.disp16 = *(uint16_t*)p;
        } else {
            hs->flags |= F_IMM16;
            hs->imm.imm16 = *(uint16_t*)p;
        }
        p += 2;
    }
    if (cflags & C_IMM8) {
        hs->flags |= F_IMM8;
        hs->imm.imm8 = *p++;
    }

    if (cflags & C_REL32) {
rel32_ok:
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t*)p;
        p += 4;
    } else if (cflags & C_REL8) {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
    }

disasm_done:

    if ((hs->len = (uint8_t)(p-(uint8_t*)code)) > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        hs->len = 15;
    }

    return (unsigned int)hs->len;
}
#endif

/****************************************** End of Hacker Disassembler code *******************************************/

void* hooker_alloc(size_t size)
{
#if _WIN32
    return VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#elif __linux__
    return mmap(0, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

void hooker_free(void* memory)
{
#if _WIN32
    VirtualFree(memory, 0, MEM_RELEASE | MEM_DECOMMIT);
#elif __linux__
    munmap(memory, 0);  // TODO: test
#endif
}

void hooker_flush_instruction_cache(void* address, size_t size)
{
#if __linux__
    const size_t cache_line = 64;
    const char *cp = (const char *)address;
    size_t i = 0;

    if (address == NULL || size == 0)
        return;

    for (i = 0; i < size; i += cache_line)
    {
        asm volatile("clflush (%0)\n\t"
        :
        : "r"(&cp[i])
        : "memory");
    }
    asm volatile("sfence\n\t"
    :
    :
    : "memory");
#elif _WIN32
    FlushInstructionCache(GetCurrentProcess(), address, size);
#endif
}

void* hooker_mem_protect(void* p, size_t size, size_t protection, size_t* original_protection)
{
#if _WIN32
    DWORD old = 0;
    DWORD flags = PAGE_NOACCESS;
    if (protection & HOOKER_MEM_PLATFORM)
        flags = (DWORD)(protection & ~HOOKER_MEM_PLATFORM);
    else
    {
        if (protection & HOOKER_MEM_R && protection & HOOKER_MEM_W && protection & HOOKER_MEM_X)
            flags = PAGE_EXECUTE_READWRITE;
        else if (protection & HOOKER_MEM_R && protection & HOOKER_MEM_W)
            flags = PAGE_READWRITE;
        else if (protection & HOOKER_MEM_R && protection & HOOKER_MEM_X)
            flags = PAGE_EXECUTE_READ;
        else if (protection & HOOKER_MEM_R)
            flags = PAGE_READONLY;
        else if (protection & HOOKER_MEM_X)
            flags = PAGE_EXECUTE;
    }
    if (VirtualProtect(p, size, flags, &old))
    {
        if (original_protection)
            *original_protection = (size_t)old | HOOKER_MEM_PLATFORM;
        return HOOKER_SUCCESS;
    }
#elif __linux__
    size_t page_size = (size_t)sysconf(_SC_PAGE_SIZE);
    void* page = (void*)((size_t)p & ~(page_size - 1));
    int flags = PROT_NONE;
    if (protection & HOOKER_MEM_PLATFORM)
        flags = (int)(protection & ~HOOKER_MEM_PLATFORM);
    else
    {
        if (protection & HOOKER_MEM_R)
            flags |= PROT_READ;
        if (protection & HOOKER_MEM_W)
            flags |= PROT_WRITE;
        if (protection & HOOKER_MEM_X)
            flags |= PROT_EXEC;
    }
    if (mprotect(page, ((size / page_size) + 1) * page_size, flags) == 0)
    {
        // Is there an easy way to get original protection flags without parsing sysfs?
        // old_protect should be set by caller for now.
        return HOOKER_SUCCESS;
    }
#endif
    return HOOKER_ERROR;
}

size_t hooker_get_mnemonic_size(void* address, size_t min_size)
{
    size_t size = 0;
    uint8_t* address_t = (uint8_t*)address;
#if HOOKER_X64
    hde64s hd;
    while (size < min_size)
        size += hde64_disasm(&address_t[size], &hd);
#else
    hde32s hd;
    while (size < min_size)
        size += hde32_disasm(&address_t[size], &hd);
#endif
    return size;
}

void* hooker_hotpatch(void* location, void* new_proc)
{
    if (*(uint16_t*)location != 0xFF8B)                                          // Verify if location is hot-patchable.
        return (void*)HOOKER_ERROR;
    hooker_hook((uint8_t*)location - 5, new_proc, HOOKER_HOOK_JMP, 0);
    size_t original_protection = HOOKER_MEM_RX;
    hooker_mem_protect(location, 2, HOOKER_MEM_RWX, &original_protection);
    *(uint16_t*)location = 0xF9EB;                                              // jump back to hotpatch
    hooker_mem_protect(location, 2, original_protection, 0);
    hooker_flush_instruction_cache((uint8_t*)location - 5, 7);
    return (uint8_t*)location + 2;
}

void* hooker_unhotpatch(void* location)
{
    if (*(uint16_t*)location != 0xF9EB)                                         // Verify that location was hotpatched.
        return (size_t)HOOKER_ERROR;
    size_t original_protection = HOOKER_MEM_RX;
    hooker_mem_protect(location, 2, HOOKER_MEM_RWX, &original_protection);
    *(uint16_t*)location = 0xFF8B;                                              // mov edi, edi = nop
    hooker_mem_protect(location, 2, original_protection, 0);
    hooker_flush_instruction_cache((uint8_t*)location, 2);
    return HOOKER_SUCCESS;
}

void hooker_nop_tail(void* address, size_t len, size_t nops)
{
    if (nops == -1)
        nops = hooker_get_mnemonic_size(address, len) - len;
    hooker_nop((uint8_t*)address + len, nops);
}

void* hooker_hook(void* address_, void* new_proc, size_t flags, size_t nops)
{
    uint8_t* address = (uint8_t*)address_;
#if HOOKER_X64
    if (flags & HOOKER_HOOK_FAT)
    {
        uint16_t opcode = 0;
        if (flags & HOOKER_HOOK_CALL)
            opcode = 0xD0FF;
        else if (flags & HOOKER_HOOK_JMP)
            opcode = 0xE0FF;
        else
            return HOOKER_ERROR;

        hooker_nop_tail(address, 12, nops);

        // Fat call/jump to 64 bit address
        size_t original_protection = HOOKER_MEM_RX;
        hooker_mem_protect(address, 12, HOOKER_MEM_RWX, &original_protection);
        *(uint16_t*)&address[0] = 0xB848;                    // movabs rax,
        *(uint64_t*)&address[2] = (uint64_t)new_proc;        // address
        *(uint16_t*)&address[10] = opcode;                   // callq|jmpq rax
        hooker_mem_protect(address, 12, original_protection, 0);
        hooker_flush_instruction_cache(address, 12);
        return HOOKER_SUCCESS;
    }
    else
#endif
    {
        uint8_t opcode = 0;
        if (flags & HOOKER_HOOK_CALL)
            opcode = 0xE8;
        else if (flags & HOOKER_HOOK_JMP)
            opcode = 0xE9;

        if (opcode)
        {
#if HOOKER_X64
            // On x64 addresses may be further away than fits into 32bits. HOOKER_HOOK_FAT should be used in these cases.
            if ((size_t)(MAX(address, (uint8_t*)new_proc) - MIN(address, (uint8_t*)new_proc)) > 0x80000000)
                return (void*)HOOKER_ERROR;
#endif
            hooker_nop_tail(address, 5, nops);

            size_t original_protection = HOOKER_MEM_RX;
            hooker_mem_protect(address, 5, HOOKER_MEM_RWX, &original_protection);
            uint8_t* location_t = address;
            *location_t = opcode;
            *(uint32_t*)(++location_t) = (uint32_t)((size_t)new_proc - (size_t)address) - 5;
            hooker_mem_protect(address, 5, original_protection, 0);
            hooker_flush_instruction_cache(address, 5);
            return HOOKER_SUCCESS;
        }
    }

    return HOOKER_ERROR;
}

void* hooker_redirect(void* address_, void* new_proc, size_t flags)
{
    uint8_t* address = (uint8_t*)address_;
#if HOOKER_X64
    size_t jmp_len = 12;
    flags |= HOOKER_HOOK_FAT;
#else
    size_t jmp_len = 5;
#endif
    size_t save_bytes = hooker_get_mnemonic_size(address, jmp_len);
    size_t bridge_size = save_bytes + jmp_len + 1;
    if (flags & HOOKER_HOOK_CALL)
        bridge_size += jmp_len;

    // JUMP Bridge: [len(original bytes)]             [original bytes] [jmp address+len(original bytes)]
    // CALL Bridge: [len(original bytes)] [call hook] [original bytes] [jmp address+len(original bytes)]
    uint8_t* bridge = (uint8_t*)hooker_alloc(bridge_size);
    // Save number of saved bytes at the start of bridge and skip a byte.
    *bridge = (uint8_t)save_bytes; bridge++;
    uint8_t* bridge_start = bridge;
    // Write a call to our hook.
    if (flags & HOOKER_HOOK_CALL)
    {
        hooker_hook(bridge, new_proc, flags, 0);
        bridge += jmp_len;
    }
    // Write overwritten instructions
    memcpy(bridge, address, save_bytes);
    bridge += save_bytes;
    // Write jump to original function
    hooker_hook(bridge, address + save_bytes, HOOKER_HOOK_JMP | HOOKER_HOOK_FAT, 0);
    // Write jump to the new proc
    if (flags & HOOKER_HOOK_CALL)
        hooker_hook(address, bridge_start, HOOKER_HOOK_JMP | HOOKER_HOOK_FAT, -1);
    else
        hooker_hook(address, new_proc, HOOKER_HOOK_JMP | HOOKER_HOOK_FAT, -1);
    // Bridge is call to original proc
    return bridge_start;
}

void hooker_unhook(void* address, void* original)
{
    // Possible call with HOOKER_SUCCESS or HOOKER_ERROR parameter.
    if (original < (void*)2)
        return;

    uint8_t restore_len = *((uint8_t*)original - 1);
    size_t original_protection = HOOKER_MEM_RX;
    hooker_mem_protect(address, restore_len, HOOKER_MEM_RWX, &original_protection);
    memcpy(address, original, restore_len);
    hooker_mem_protect(address, restore_len, original_protection, 0);
    hooker_free((uint8_t*)original - 1);
    hooker_flush_instruction_cache(address, restore_len);
}

size_t* hooker_get_vmt_address(void* object, void* method)
{
    size_t* vmt = *(size_t**)object;
    while (*vmt != (size_t)method)
        vmt++;
    return vmt;
}

void* hooker_find_pattern(void* start, int size, const uint8_t* pattern, size_t pattern_len, uint8_t wildcard)
{
    if (start == 0 || pattern == 0 || pattern_len == 0)
        return 0;

    uint8_t* p = (uint8_t*)start;
    uint8_t* end = (uint8_t*)~0;
    int step = 1;
    if (size > 0)
        end = &p[size - pattern_len];
    else if (size < 0)
    {
        step = -1;
        p -= pattern_len;
        end = &p[size];
    }

    while (step > 0 ? p < end : p >= end)
    {
    pattern_search:
        for (size_t i = 0; i < pattern_len; i++)
        {
            if (p[i] != pattern[i] && pattern[i] != wildcard)
            {
                p += step;
                goto pattern_search;
            }
        }
        return p;
    }

    return 0;
}

void* hooker_find_pattern_ex(void* start, int size, const uint8_t* pattern, size_t pattern_len, const uint8_t* wildcard)
{
    if (start == 0 || pattern == 0 || pattern_len == 0)
        return 0;

    uint8_t* p = (uint8_t*)start;
    uint8_t* end = (uint8_t*)~0;
    int step = 1;
    if (size > 0)
        end = &p[size - pattern_len];
    else if (size < 0)
    {
        step = -1;
        p -= pattern_len;
        end = &p[size];
    }

    while (step > 0 ? p < end : p >= end)
    {
    pattern_search:
        for (size_t i = 0; i < pattern_len; i++)
        {
            uint8_t byte = p[i];
            uint8_t value = pattern[i];
            switch (wildcard[i])
            {
            case 1:
                // First half of byte to ignore, keep only second half.
                byte &= 0xF0;
                value &= 0xF0;
                break;
            case 2:
                // Second half of byte to ignore, keep only first half.
                byte &= 0x0F;
                value &= 0x0F;
                break;
            case 3:
                // Ignore entire byte.
                byte = 0;
                value = 0;
                break;
            default:
                // Not a wildcard.
                break;
            }

            if (byte != value)
            {
                p += step;
                goto pattern_search;
            }
        }
        return p;
    }

    return 0;
}

void* hooker_nop(void* start, size_t size)
{
    if (start == 0 || size == 0)
        return HOOKER_ERROR;

    size_t original = HOOKER_MEM_RX;
    if (hooker_mem_protect(start, size, HOOKER_MEM_RWX, &original) != HOOKER_SUCCESS)
        return HOOKER_ERROR;
    memset(start, 0x90, size);
    hooker_mem_protect(start, size, original, 0);
    hooker_flush_instruction_cache(start, size);
    return HOOKER_SUCCESS;
}

void* hooker_write(void* start, void* data, size_t size)
{
    if (start == 0 || size == 0)
        return HOOKER_ERROR;

    size_t original = HOOKER_MEM_RX;
    if (hooker_mem_protect(start, size, HOOKER_MEM_RWX, &original) == HOOKER_SUCCESS)
    {
        memcpy(start, data, size);
        hooker_mem_protect(start, size, original, 0);
        hooker_flush_instruction_cache(start, size);
        return HOOKER_SUCCESS;
    }
    return HOOKER_ERROR;
}

void* hooker_dlsym(const char* lib_name, const char* sym_name)
{
#if _WIN32
    HMODULE mod = GetModuleHandleA(lib_name);
    if (mod == 0)
    {
        mod = LoadLibraryA(lib_name);
        if (mod == 0)
            return 0;
    }

    return GetProcAddress(mod, sym_name);
#elif __linux__
    void* mod = dlopen(lib_name, RTLD_GLOBAL | RTLD_NODELETE);
    if (mod == 0)
        return 0;
    void* sym = dlsym(mod, sym_name);
    dlclose(mod);
    return sym;
#endif
}

#if _WIN32
void* hooker_hook_iat(const char* mod_name, const char* imp_mod_name, const char* imp_proc_name, void* new_proc)
{
    if (mod_name == 0 || imp_mod_name == 0 || imp_proc_name == 0 || new_proc == 0)
        return HOOKER_ERROR;

    void* result = 0;
    uintptr_t module_base = (uintptr_t)GetModuleHandleA(mod_name);
    if (module_base == 0)
        module_base = (uintptr_t)LoadLibraryA(mod_name);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(module_base + dos->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR import_dir;

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return HOOKER_ERROR;

    import_dir = (PIMAGE_IMPORT_DESCRIPTOR)(module_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (unsigned i = 0; import_dir[i].Characteristics != 0; i++)
    {
        const char* import_name = (const char*)(module_base + import_dir[i].Name);
        if (_strcmpi(import_name, imp_mod_name) != 0)
            continue;

        PIMAGE_THUNK_DATA thunk;
        PIMAGE_THUNK_DATA thunk_orig;

        if (!import_dir[i].FirstThunk || !import_dir[i].OriginalFirstThunk)
            return HOOKER_ERROR;

        thunk = (PIMAGE_THUNK_DATA)(module_base + import_dir[i].FirstThunk);
        thunk_orig = (PIMAGE_THUNK_DATA)(module_base + import_dir[i].OriginalFirstThunk);

        for (; thunk_orig->u1.Function != 0; thunk_orig++, thunk++)
        {
            if (thunk_orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                // Ordinals unsupported
                continue;

            PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)(module_base + thunk_orig->u1.AddressOfData);
            if (strcmp(imp_proc_name, (const char*)import->Name) != 0)
                continue;

            result = (PVOID)(uintptr_t)thunk->u1.Function;
            if (hooker_write(&thunk->u1.Function, &new_proc, sizeof(new_proc)) == HOOKER_SUCCESS)
                return result;
        }
    }

    return HOOKER_ERROR;
}
#endif
