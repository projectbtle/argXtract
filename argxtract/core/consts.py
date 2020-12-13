from capstone.arm import *

# Analysis mode.
MODE_SVC = 'svc'
MODE_FUNCTION = 'function'

# ARM architecture.
ARMv6M = 'armv6m'
ARMv7M = 'armv7m'

# Functions.
FN_MEMSET = 'memset'
FN_UDIV = 'udiv'
FN_ARMSWITCH8 = 'switch8'
FN_ARMSWITCH8CALL = 'switch8-call'
FN_GNUTHUMB = 'gnu-thumb'
FN_GNUTHUMBCALL = 'gnu-thumb-call'
PC_SWITCH = 'pc_switch'

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
    ARM_REG_R0: "r0",
	ARM_REG_R1: "r1",
	ARM_REG_R2: "r2",
	ARM_REG_R3: "r3",
	ARM_REG_R4: "r4",
	ARM_REG_R5: "r5",
	ARM_REG_R6: "r6",
	ARM_REG_R7: "r7",
	ARM_REG_R8: "r8",
	ARM_REG_R9: "r9",
	ARM_REG_R10: "r10",
	ARM_REG_R11: "r11",
	ARM_REG_R12: "r12",
	ARM_REG_R13: "r13",
	ARM_REG_R14: "r14",
	ARM_REG_R15: "r15",
    ARM_REG_LR: "lr",
	ARM_REG_PC: "pc",
	ARM_REG_SP: "sp",
    ARM_REG_SB: "sb",
    ARM_REG_SL: "sl",
    ARM_REG_FP: "fp",
    ARM_REG_IP: "ip"
}
