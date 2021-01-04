import os
import sys
import struct
import logging
import numpy as np
from capstone.arm import *
from argxtract.common import paths as common_paths
from argxtract.core import consts
from argxtract.common import objects as common_objs


def id_function_block_for_instruction(ins_address):
    function_block_starts = list(common_objs.function_blocks.keys())
    function_block_starts.sort()
    if ins_address in function_block_starts:
        return ins_address
    
    len_function_starts = len(function_block_starts)        
    closest = function_block_starts[min(range(len_function_starts),
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
    all_addresses.sort()
    function_block_starts = list(common_objs.function_blocks.keys())
    curr_index = function_block_starts.index(function_block_start)
    if curr_index < (len(function_block_starts)-1):
        next_function_start = (function_block_starts[curr_index+1])
        next_function_index = all_addresses.index(next_function_start)
        block_end = all_addresses[next_function_index-1]
    else:
        block_end = common_objs.code_end_address
    return block_end
    
def sort_dict_keys(dictionary):
    keys = list(dictionary.keys())
    keys.sort()
    sorted_dictionary = {}
    for key in keys:
        sorted_dictionary[key] = dictionary[key]
    return sorted_dictionary
    
def convert_type(value, dtype, byte_length='default', signed=None):
    if dtype == 'int':
        if type(value) is int:
            if value > 2147483647:
                value = np.uint32(value)
            else:
                value = np.int32(value)
        elif type(value) is str:
            length = len(value)
            value = int(value, 16)
            if length == 2:
                if signed == True:
                    value = np.int8(value)
                elif signed == False:
                    np.uint8(value)
                else:
                    if value > 127:
                        value = np.uint8(value)
                    else:
                        value = np.int8(value)
            elif length == 4:
                if signed == True:
                    value = np.int16(value)
                elif signed == False:
                    value = np.uint16(value)
                else:
                    if value > 32767:
                        value = np.uint16(value)
                    else:
                        value = np.int16(value)
            elif length == 8:
                if signed == True:
                    value = np.int32(value)
                elif signed == False:
                    value = np.uint32(value)
                else:
                    if value > 2147483647:
                        value = np.uint32(value)
                    else:
                        value = np.int32(value)
    elif dtype == 'hex':
        if type(value) is str:
            value = value
        elif type(value) is np.int8:
            value = '{0:02x}'.format(value)
        elif type(value) is np.uint8:
            value = '{0:02x}'.format(value)
        elif type(value) is np.int16:
            value = '{0:04x}'.format(value)
        elif type(value) is np.uint16:
            value = '{0:04x}'.format(value)
        elif type(value) is np.int32:
            value = '{0:08x}'.format(value)
        elif type(value) is np.uint32:
            value = '{0:08x}'.format(value)
        elif type(value) is np.int64:
            value = '{0:08x}'.format(value)
        elif type(value) is int:
            value = '{0:08x}'.format(value)
        elif type(value) is bytes:
            value = value.hex()
    elif dtype == 'bytes':
        if type(value) is str:
            value = bytes.fromhex(value)
        elif type(value) is int:
            if byte_length == 'default': 
                byte_length = (value.bit_length() + 7) // 8
            value = (value).to_bytes(
                byte_length, 
                byteorder='big'
            )
        elif type(value) is bytes:
            value = value
    elif dtype == 'bin':
        if type(value) is np.int32:
            value = get_binary_representation(value, 32)
        elif type(value) is np.uint32:
            value = get_binary_representation(value, 32)
        elif type(value) is np.int64:
            value = get_binary_representation(value, 32)
        elif type(value) is int:
            value = get_binary_representation(value, 32)
        elif type(value) is np.int16:
            value = get_binary_representation(value, 16)
        elif type(value) is np.uint16:
            value = get_binary_representation(value, 16)
        elif type(value) is np.int8:
            value = get_binary_representation(value, 8)
        elif type(value) is np.uint8:
            value = get_binary_representation(value, 8)
        elif type(value) is str:
            bin_len = len(str) * 4
            value = get_binary_representation(
                int(value, 16),
                bin_len
            )
    return value
    
def get_bit_length(value):
    bit_length = None
    if ((type(value) is np.uint32) or (type(value) is np.int32)):
        bit_length = 32
    elif ((type(value) is np.uint16) or (type(value) is np.int16)):
        bit_length = 16
    elif ((type(value) is np.uint8) or (type(value) is np.int8)):
        bit_length = 8
    elif (type(value) is str):
        if len(value) == 8:
            bit_length = 32
        elif len(value) == 4:
            bit_length = 16
        elif len(value) == 2:
            bit_length = 8
    if bit_length == None: 
        print(type(value))
        logging.error('WHAT')
    return bit_length
    
def get_binary_representation(value, length):
    if value == None: return None
    if type(value) is str:
        binary = bin(int('1'+value, 16))[3:]
        binary = binary.zfill(length)
    else:
        binary = np.binary_repr(value, width=length)
    return binary          
    
def convert_bits_to_type(bitstring, dtype):
    if ((dtype is str) or (dtype == 'hex')):
        integer_value = int(bitstring, 2)
        bit_length = len(bitstring)
        mult = 0xFFFFFFFF
        if bit_length == 8:
            mult = 0xFF
        elif bit_length == 16:
            mult = 0xFFFF
        new_value = (~integer_value & mult)
    else:
        python_int = int(bitstring, 2)
        if dtype == np.int8:
            try:
                decimal_value = np.int8(int(bitstring, 2))
            except:
                decimal_value = np.uint8(int(bitstring, 2))
        elif dtype == np.uint8:
            if python_int < 0:
                decimal_value = np.int8(int(bitstring, 2))
            else:
                decimal_value = np.uint8(int(bitstring, 2))
        elif dtype == np.int16:
            try:
                decimal_value = np.int16(int(bitstring, 2))
            except:
                decimal_value = np.uint16(int(bitstring, 2))
        elif dtype == np.uint16:
            if python_int < 0:
                decimal_value = np.int16(int(bitstring, 2))
            else:
                decimal_value = np.uint16(int(bitstring, 2))
        elif dtype == np.int32:
            try:
                decimal_value = np.int32(int(bitstring, 2))
            except:
                decimal_value = np.uint32(int(bitstring, 2))
        elif dtype == np.uint32:
            if python_int < 0:
                decimal_value = np.int32(int(bitstring, 2))
            else:
                decimal_value = np.uint32(int(bitstring, 2))
        new_value = decimal_value.astype(dtype)
    return new_value
    
def reverse_bytes(bytes):
    hex_bytes = bytes.hex()
    ba = bytearray.fromhex(hex_bytes)
    ba.reverse()
    reversed_hex = ''.join(format(x, '02x') for x in ba)
    reversed_bytes = bytes.fromhex(reversed_hex)
    return reversed_bytes

def get_numpy_type(values):
    dtype = np.int8
    for value in values:
        val_type = type(value)
        if dtype == np.int8:
            dtype = val_type
        elif dtype == np.uint8:
            if val_type == np.int8:
                continue
            dtype = val_type
        elif dtype == np.int16:
            if ((val_type == np.int8) 
                    or (val_type == np.uint8)):
                continue
            dtype = val_type
        elif dtype == np.uint16:
            if ((val_type == np.int8) 
                    or (val_type == np.uint8) 
                    or (val_type == np.int16)):
                continue
            dtype = val_type
        elif dtype == np.int32:
            if val_type == np.uint32:
                dtype = val_type
    return dtype
    
def get_firmware_bytes(address, num_bytes=4, dtype='hex', 
        endian=common_objs.endian):
    address = address - common_objs.disassembly_start_address
    end_address = address + num_bytes
    data_bytes = None
    remaining_bytes = num_bytes
    value = None
    while remaining_bytes > 0:
        format_string = '<'
        if remaining_bytes >= 4:
            format_string += 'I'
            end_address = address + 4
            obtained_bytes = 4
        elif remaining_bytes >= 2:
            format_string += 'H'
            end_address = address + 2
            obtained_bytes = 2
        else:
            format_string += 'B'
            end_address = address + 1
            obtained_bytes = 1
        data_bytes = common_objs.core_bytes[address:end_address]
        if endian == 'little':
            mem_value = reverse_bytes(data_bytes)
        else:
            mem_value = data_bytes
        mem_value = convert_type(mem_value, 'hex')
        
        if value == None:
            value = mem_value
        else:
            value = value + mem_value
        remaining_bytes -= obtained_bytes
        address += obtained_bytes
    # Type conversion.
    value = convert_type(value, dtype)
    return value
    
def get_next_address(list_obj, item):
    if list_obj == None: return None
    if item == None: return None
    
    if type(list_obj) is dict:
        list_obj = list(list_obj.keys())
        list_obj.sort()
            
    if item not in list_obj:
        logging.trace('Item not in list. Estimating position.')
        for x in range(len(list_obj)-1, -1, -1):
            address = list_obj[x]
            if item > address:
                item = address
                break
    if item not in list_obj: 
        logging.trace('Item not in list. Returning None.')
        return None
    
    # Find index of the address and get next one up.
    if (list_obj.index(item)) < (len(list_obj) - 1):
        next_address = list_obj[list_obj.index(item) + 1]
    else:
        next_address = None
    return next_address
    
def get_previous_address(address_obj, address):
    if address_obj == None: return None
    if address == None: return None
    
    if address in address_obj:
        index = address_obj.index(address)
        if index == 0:
            return None
        prev_address = address_obj[index - 1]
    else:
        prev_address = get_previous_partial_address(
            address_obj,
            address
        )
    return prev_address

def get_previous_partial_address(address_obj, address):
    if address_obj == None: return None
    if address == None: return None
        
    if address not in address_obj:
        for i in range(1,4):
            if (address-i) in address_obj:
                address = address-i
                break
    return address
    
def is_valid_code_address(address, exclude_error_check=False):
    if address not in common_objs.disassembled_firmware:
        return False
    if (exclude_error_check==False):
        if address in common_objs.errored_instructions:
            return False
    if common_objs.disassembled_firmware[address]['is_data'] == True:
        return False
    if common_objs.disassembled_firmware[address]['insn'] == None:
        return False    
    if common_objs.disassembled_firmware[address]['insn'].id == ARM_INS_INVALID:
        return False
    return True
    
def order_dict(dictionary):
    """From https://stackoverflow.com/a/47882384."""
    return {k: order_dict(v) if isinstance(v, dict) else v
            for k, v in sorted(dictionary.items())}