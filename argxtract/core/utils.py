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
    
def sort_dict_keys(dictionary):
    keys = list(dictionary.keys())
    keys.sort()
    sorted_dictionary = {}
    for key in keys:
        sorted_dictionary[key] = dictionary[key]
    return sorted_dictionary
    