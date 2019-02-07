"""
Helper constructs for parsing the MIPS instruction set.
This module will be imported along with 'from mwcp.utils import construct'
and accessible from the submodule "MIPS". (e.g. construct.MIPS.lw)

reference: github.com/MIPT-ILab/mipt-mips/wiki/MIPS-Instruction-Set
"""

from .version28 import *
from .version28 import this


_REGISTERS = {
    '$zero': 0,
    '$at': 1,
    '$v0': 2, '$v1': 3,
    '$a0': 4, '$a1': 5, '$a2': 6, '$a3': 7,
    '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11, '$t4': 12, '$t5': 13, '$t6': 14, '$t7': 15,
    '$s0': 16, '$s1': 17, '$s2': 18, '$s3': 19, '$s4': 20, '$s5': 21, '$s6': 22, '$s7': 23,
    '$t8': 24, '$t9': 25,
    '$k0': 26, '$k1': 27,
    '$gp': 28, '$sp': 29, '$fp': 30, '$ra': 31,
}
_Register = Enum(BitsInteger(5), **_REGISTERS)

# I-type instruction
_I_inst = Struct(
    Embedded(BitStruct(
        'opcode' / Enum(
            BitsInteger(6),
            # NOTE: Some opcode values are reserved for other instruction formats
            # and we should let construct fail if it sees one.
            j=0x02, jal=0x03, beq=0x04, bne=0x05, blez=0x06, bgtz=0x07,
            addi=0x08, addiu=0x09, slti=0x0A, sltiu=0x0B, andi=0x0C, ori=0x0D, xori=0x0E, lui=0x0F,
            beql=0x14, bnel=0x15, blezl=0x16, bgtzl=0x17,
            daddi=0x18, daddiu=0x19, ldl=0x1A, ldr=0x1B, jalx=0x1D,
            lb=0x20, lh=0x21, lwl=0x22, lw=0x23, lbu=0x24, lhu=0x25, lwr=0x26, lwu=0x27,
            sb=0x28, sh=0x29, swl=0x2A, sw=0x2B, sdl=0x2C, sdr=0x2D, swr=0x2E, cache=0x2F,
            ll=0x30, lwc1=0x31, lwc2=0x32, pref=0x33, lld=0x34, ldc1=0x35, ldc2=0x36, ld=0x37,
            sc=0x38, swc1=0x39, swc2=0x3A, scd=0x3C, sdc1=0x3D, sdc2=0x3E, sd=0x3F,
        ),
        'src_register' / _Register,
        'target_register' / _Register,
        # 'imm_constant' / construct.BitsInteger(16)
    )),
    # Need to move immediate outside of BitStruct to create signed number.
    # (Luckly, the constant is byte aligned)
    'imm_constant' / Int16sb
)


lw = ExprValidator(_I_inst, this.opcode == 'lw')

# TODO: Create a MIPS version of ELFPointer that will account for the Global Offset Table and $gp register
# from extracted "la" psuedo instructions.
