import os
import sys
import struct
import logging
from capstone.arm import *
from argxtract.common import paths as common_paths
from argxtract.core import consts
from argxtract.common import objects as common_objs


def id_function_block_for_instruction(ins_address):
    function_block_starts = list(common_objs.function_blocks.keys())
    function_block_starts.sort()
    if ins_address in function_block_starts:
        return ins_address
        
    closest = function_block_starts[min(range(len(function_block_starts)),
        key = lambda i: abs(function_block_starts[i]-ins_address))]
        
    if closest <= ins_address:
        return closest

    index_of_closest = function_block_starts.index(closest)
    # Make sure we don't loop backwards to end.
    minimum_possible_address = common_objs.code_start_address
    if ((index_of_closest - 1) < 0):
        block_start = minimum_possible_address
    else:
        block_start = function_block_starts[index_of_closest - 1]
    return block_start
    
def id_function_block_end(function_block_start):
    all_addresses = list(common_objs.disassembled_firmware.keys())
    function_block_starts = list(common_objs.function_blocks.keys())
    curr_index = function_block_starts.index(function_block_start)
    if curr_index < (len(function_block_starts)-1):
        next_function_start = (function_block_starts[curr_index+1])
        next_function_index = all_addresses.index(next_function_start)
        block_end = all_addresses[next_function_index-1]
    else:
        block_end = all_addresses[-1]
    return block_end
    
def test_gcc_vs_other():
    image_file = open(common_paths.path_to_fw, 'rb').read().hex()
    if 'df7047' in image_file:
        common_objs.compiler = consts.COMPILER_GCC
    else:
        common_objs.compiler = consts.COMPILER_NON_GCC
        
    logging.debug(
        'Compiler estimated to be: '
        + common_objs.compiler
    )
    
def sort_dict_keys(dictionary):
    keys = list(dictionary.keys())
    keys.sort()
    sorted_dictionary = {}
    for key in keys:
        sorted_dictionary[key] = dictionary[key]
    return sorted_dictionary
    
def analyse_vector_table(path_to_fw, base=0):
    application_vector_table = {}
    image_file = open(path_to_fw, 'rb')
    for avt_entry in consts.AVT.keys():
        image_file.seek(0)
        image_file.seek(base+consts.AVT[avt_entry])
        vector_table_entry = struct.unpack('<I', image_file.read(4))[0]
        if vector_table_entry == 0x00000000:
            continue
        if vector_table_entry%2 == 1:
            vector_table_entry -= 1
        application_vector_table[avt_entry] = vector_table_entry
    
    common_objs.application_vector_table = application_vector_table
    debug_msg = 'Partial Application Vector Table:'
    for avt_entry in application_vector_table:
        debug_msg += '\n\t\t\t\t' \
                     + avt_entry \
                     + ': ' \
                     + hex(application_vector_table[avt_entry]) 
    logging.info(debug_msg)
