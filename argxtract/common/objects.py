import os
import sys
import json
from argxtract.common import paths as common_paths
from argxtract.core import consts

#============ Generic variables ============
max_time = 300
mode = consts.MODE_SVC
vendor = None
endian = 'little'
allow_loops = True
max_call_depth = 1
null_value_handling = consts.NULL_HANDLING_NONE
bypass_all_conditional_checks = False

#========== File-specific variables =========
arm_arch = consts.ARMv6M

# Firmware breakdown.
app_code_base = 0x00000000
disassembly_start_address = 0x00000000
code_start_address = 0x00000000
code_end_address = 0x00000000
data_segment_start_address = 0x00000000
data_segment_start_firmware_address = 0x00000000
flash_length = 0x00000000
ram_base = 0x00000000
ram_length = 0x00000000
vector_table_size = 0
application_vector_table = {}
self_targeting_branches = []
core_bytes = None
disassembled_firmware = {}
data_region = {}
errored_instructions = []
function_blocks = {}
replace_functions = {}
denylisted_functions = []
coi_addresses = {}
table_branches = {}

# Tracing objects.
coi_chains = []
coi_function_blocks = []
potential_start_points = []