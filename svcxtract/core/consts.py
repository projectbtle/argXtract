from capstone.arm import *

# Compiler type.
COMPILER_GCC = 'gcc'
COMPILER_NON_GCC = 'non_gcc'

# Functions.
MEMSET = 'memset'

# Address types.
ADDRESS_DATA = 'data'
ADDRESS_FIRMWARE = 'firmware'
ADDRESS_RAM = 'ram'
ADDRESS_STACK = 'stack'

# Null value handling.
NULL_HANDLING_NONE = 'n'
NULL_HANDLING_LOOSE = 'l'
NULL_HANDLING_STRICT = 's'

# Error codes
ERROR_INVALID_INSTRUCTION = 'error_invalid_ins'

# ARM conditional modifiers.
CONDITIONALS = [
    'eq','ne','cs','cc',
    'mi','pl','vs','vc',
    'hi','ls','ge','lt',
    'gt','le','al'
]

# App Vector Table.
AVT = {
    'initial_sp': 0x0000,
    'reset': 0x0004,
    'nmi': 0x0008,
    'hard_fault': 0x000C,
    'mem_mgmt_fault': 0x0010,
    'bus_fault': 0x0014,
    'usage_fault': 0x0018,
    'svc': 0x002C,
    'pendsv': 0x0038,
    'systick': 0x003C
}

# Register aliases.
REGISTERS = {
    ARM_REG_R0,
	ARM_REG_R1,
	ARM_REG_R2,
	ARM_REG_R3,
	ARM_REG_R4,
	ARM_REG_R5,
	ARM_REG_R6,
	ARM_REG_R7,
	ARM_REG_R8,
	ARM_REG_R9,
	ARM_REG_R10,
	ARM_REG_R11,
	ARM_REG_R12,
	ARM_REG_R13,
	ARM_REG_R14,
	ARM_REG_R15,
    ARM_REG_LR,
	ARM_REG_PC,
	ARM_REG_SP,
    ARM_REG_SB,
    ARM_REG_SL,
    ARM_REG_FP,
    ARM_REG_IP
}