import os
import sys
import json
import struct
import logging
import numpy as np
from capstone import *
from capstone.arm import *
from random import getrandbits
from collections import Counter 
from svcxtract.common import paths as common_paths
from svcxtract.core import utils
from svcxtract.core import consts
from svcxtract.common import objects as common_objs
from svcxtract.core.chipset_analyser import ChipsetAnalyser
from svcxtract.core.register_evaluator import RegisterEvaluator


class SvcAnalyser:
    def __init__(self):
        self.chipset_analyser = ChipsetAnalyser()
        self.reg_eval = RegisterEvaluator()
        
    def set_vendor_paths(self):
        self.svc_definition_dir = os.path.join(
            common_paths.resources_path,
            'vendor',
            common_objs.vendor,
            'svc'
        )
        
    def create_svc_object(self):
        svc_object = {}
        for ins_address in common_objs.disassembled_firmware:
            if ins_address < common_objs.code_start_address:
                continue
            if ins_address in common_objs.errored_instructions:
                continue
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
            
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            
            # Only consider SVC instructions.
            if (insn.id != ARM_INS_SVC):
                continue
                
            # Get svc call.
            svc_call = insn.operands[0].value.imm
            
            # Add SVC number to SVC object.
            if svc_call not in svc_object:
                svc_object[svc_call] = {
                    'callers': []
                }
            
            # Treat GCC and non-GCC separately.
            if common_objs.compiler == consts.COMPILER_GCC:
                if ('xref_from' not in 
                        common_objs.disassembled_firmware[ins_address]):
                    if ins_address not in common_objs.errored_instructions:
                        common_objs.errored_instructions.append(ins_address)
                    continue
                for item in common_objs.disassembled_firmware[ins_address]['xref_from']:
                    if item not in svc_object[svc_call]['callers']:
                        svc_object[svc_call]['callers'].append(item)
            else:
                if ins_address not in svc_object[svc_call]['callers']:
                    svc_object[svc_call]['callers'].append(ins_address)
                    
        # Clean-up. Remove any calls that don't have xref_from.
        new_svc_object = {}
        for svc_call in svc_object:
           if svc_object[svc_call]['callers'] != []:
               new_svc_object[svc_call] = svc_object[svc_call]
               
        # Assign object to common objs, and cleanup.
        common_objs.svc_calls = new_svc_object
        svc_object = None
        new_svc_object = None
        
    def find_all_svc_chains(self, svc_call, store=True):
        """Find all call chains tracing backwards from an SVC call."""
        all_svc_chains = []
        fblock_list = []
        
        logging.debug('Looking for SVC chains for SVC num: ' + hex(svc_call))
        
        if svc_call not in common_objs.svc_calls:
            logging.debug(
                '[svc_analyser] SVC number '
                + hex(svc_call)
                + ' not present in SVC object.'
            )
            return (all_svc_chains, fblock_list)

        # First get all instructions that make SVC calls.
        # With GCC, this will be instruction that calls a function that 
        #  makes an SVC call.
        xrefs_from_svc = common_objs.svc_calls[svc_call]['callers']
        
        starting_points = []
        # For every instruction that makes an SVC call, identify the function
        #  block that it belongs to.
        # This is the starting point for the SVC call chain.
        for xref_from_svc in xrefs_from_svc:
            function_block = utils.id_function_block_for_instruction(
                xref_from_svc
            )
            if function_block not in fblock_list:
                fblock_list.append(function_block)
            svcxref_functionblock = str(xref_from_svc) + ':' + str(function_block)
            starting_points.append(svcxref_functionblock)
        starting_points = list(set(starting_points))
        
        # For each call to SVC, get the call chain.
        for starting_point in starting_points:
            self.get_chain(starting_point, '', all_svc_chains, fblock_list)
        
        if len(all_svc_chains) == 0:
            logging.info('No SVC chains identified.')
            return (all_svc_chains, fblock_list)
            
        all_svc_chains.sort()
        
        debug_msg = 'SVC chains:\n'
        for item in all_svc_chains:
            debug_msg += '\t\t\t\t' + str(item) + '\n'
        logging.debug(debug_msg)
        
        if store == True:
            common_objs.svc_chains = all_svc_chains
        else:
            return (all_svc_chains, fblock_list)
    
    def get_chain(self, xref_fblock, chain, output_list, fblock_list):
        if chain == '':
            chain = xref_fblock
        else:
            chain = chain + ',' + xref_fblock

        xref = int(xref_fblock.split(':')[0])
        func_block = int(xref_fblock.split(':')[1])
        
        # Check for calls to this function block.
        xrefs_from = common_objs.function_blocks[func_block]['xref_from']
        
        # If there are no calls to this function block, perhaps it's the 
        #  end of the chain, i.e., the starting point.
        # Add it to the list and return.
        if xrefs_from == None:
            output_list.append(chain)
            return
        
        # If there are calls to this function block, get xrefs for the 
        #  "callers" (the xref_froms).
        callers = []
        for xref_from in xrefs_from:
            function_block = utils.id_function_block_for_instruction(
                xref_from
            )
            # If it's self-references, ignore.
            if function_block == func_block:
                continue
                
            if function_block not in fblock_list:
                fblock_list.append(function_block)
                
            xref_functionblock = str(xref_from) + ':' + str(function_block)
            
            # If this item is already in chain, then we would just be looping 
            #  over and over. Stop at this point instead?
            split_chain = chain.split(',')
            if xref_functionblock in split_chain:
                output_list.append(chain)
                continue
                
            callers.append(xref_functionblock)
        callers = list(set(callers))
        
        # Recursively check.
        for caller in callers:
            self.get_chain(caller, chain, output_list, fblock_list)
           
    def find_starting_point_from_chain(self, chain):
        start_point = chain.split(',')[-1]
        if start_point.strip() == '':
            return None
        return start_point 
                
    def find_starting_points_from_chains(self, store=True):
        all_start_points = []
        for svc_chain in common_objs.svc_chains:
            start_point = svc_chain.split(',')[-1]
            if start_point.strip() == '':
                continue
            all_start_points.append(start_point)
            
        start_points_by_freq = [item for items, c in 
                                    Counter(all_start_points).most_common()
                                      for item in [items] * c] 
        all_start_points = None
        ordered_start_points = []
        for start_point in start_points_by_freq:
            if start_point not in ordered_start_points:
                ordered_start_points.append(start_point)
        start_points_by_freq = None
        
        if len(ordered_start_points) == 0:
            logging.info('No starting points identified.')
            return ordered_start_points
            
        debug_msg = 'Ordered list of potential starting points ' \
                    + '(ordered by frequency): \n'
        for ordered_start_point in ordered_start_points:
            debug_msg += '\t\t\t\t' + str(ordered_start_point) + '\n'
        logging.debug(debug_msg)
        
        if store == True:
            common_objs.potential_start_points = ordered_start_points
        else:
            return ordered_start_points
        
    def get_svc_num(self, svc_name):
        if ((common_objs.svc_set != None) and 
                (common_objs.svc_set != {})):
            if svc_name in common_objs.svc_set:
                svc_num = common_objs.svc_set[svc_name]
                return svc_num
        else:
            return self.chipset_analyser.get_svc_num(svc_name)
        
    def get_svc_files(self):
        svc_files = []
        vendor_dir = os.path.join(
            common_paths.resources_path,
            'vendor',
            common_objs.vendor,
            'svc'
        )
        for root, dirs, filenames in os.walk(vendor_dir):
            for filename in filenames:
                if filename.endswith('.json'):
                    svc_files.append(os.path.join(root, filename))
        return svc_files
        
    def process_svc_chains(self):
        self.output_object = {
            'output': {},
            'memory': {},
            'svcs': []
        }
        
        # Get all SVC chains.
        svc_list = self.get_svc_files()
        if len(svc_list) == 0:
            logging.critical('No SVC definition files found!')
            return

        processing_object = {}
        all_fblocks = []
        for svc_file in svc_list:
            svc_name = (os.path.basename(svc_file)).replace('.json', '')
            # Get the SVC identifier.
            svc_num = self.get_svc_num(svc_name)
            if svc_num == None:
                continue
            # Get call chains.
            (svc_chains, fblocks) = self.find_all_svc_chains(
                svc_call=int(svc_num, 16),
                store=False
            )
            if len(svc_chains) > 0:
                self.output_object['svcs'].append(svc_name)
            processing_object[svc_name] = svc_chains
            for fblock in fblocks:
                if fblock not in all_fblocks:
                    all_fblocks.append(fblock)
        # Combine the outputs, to reduce trace time.
        combined_trace_object = self.combine_svc_traces(processing_object)
        
        # Save the function blocks in common_objs, so that we don't 
        #  accidentally blacklist them.
        common_objs.svc_function_blocks = all_fblocks
        
        # Get output from register trace.
        unhandled = self.reg_eval.estimate_reg_values_for_trace_object(
            combined_trace_object,
            self
        )
        self.output_object['unhandled'] = unhandled
        # Process according to SVC definitions.
        return self.output_object
        
    def combine_svc_traces(self, all_svc_object):
        output_object = {}
        for svc_name in all_svc_object:
            list_svc_chain = all_svc_object[svc_name]
            for svc_chain in list_svc_chain:
                output_object = self.add_chain_to_trace_object(
                    output_object,
                    svc_chain,
                    svc_name
                )
        return output_object
    
    def add_chain_to_trace_object(self, output_object, svc_chain, svc_name):
        combined_object = output_object
        chain_elements = svc_chain.split(',')
        chain_elements.reverse()
        while len(chain_elements) > 0:
            ins_address = int(chain_elements[0].split(':')[0])
            function_block = int(chain_elements[0].split(':')[1])
            if function_block not in combined_object:
                combined_object[function_block] = {
                    'branch_or_end_points': {}
                }
            
            working_object = combined_object[function_block]['branch_or_end_points']
            if ins_address not in working_object:
                working_object[ins_address] = {
                    'is_end': False,
                    'svc_name': None,
                    'branch_target': {}
                }
            if len(chain_elements) == 1:
                working_object[ins_address]['is_end'] = True
                working_object[ins_address]['svc_name'] = svc_name
            combined_object = working_object[ins_address]['branch_target']
            chain_elements = chain_elements[1:]
        return output_object
    
    def annotate_trace_object(self, trace_obj, level):
        output_object = trace_obj
        for key in output_object:
            identifier = str(level) + '-' + str(self.global_annotatation_id)
            self.global_annotatation_id += 1
            output_object[key]['id'] = identifier
            level += 1
            for point in output_object[key]['branch_or_end_points']:
                point_id = str(level) + '-' + str(self.global_annotatation_id)
                self.global_annotatation_id += 1
                output_object[key]['branch_or_end_points'][point]['id'] = point_id
                output_object[key]['branch_or_end_points'][point]['branch_target'] = \
                    self.annotate_trace_object(
                        output_object[key]['branch_or_end_points'][point]['branch_target'],
                        level+1
                    )
        return output_object
        
    def process_trace_output(self, trace_output):
        svc_name = list(trace_output.keys())[0]
        if svc_name not in self.output_object['output']:
            self.output_object['output'][svc_name] = []

        # Match up with SVC definitions per output item.
        for item in trace_output:
            # First assign all existing memory addresses.
            # Otherwise we lose this information.
            self.output_object['memory'] = self.update_memory(
                self.output_object['memory'],
                trace_output[item]['memory']
            )
            
            # Now match SVC definition.
            output_item = self.match_svc_definition(
                trace_output[svc_name],
                svc_name
            )
            is_object_already_present = False
            for element in self.output_object['output'][svc_name]:
                if element == output_item['output']:
                    is_object_already_present = True
                    break
            if is_object_already_present == False:
                self.output_object['output'][svc_name].append(output_item['output'])
            # If SVC definition had output values to update in memory,
            #  do that now.
            self.output_object['memory'] = self.update_memory(
                self.output_object['memory'],
                output_item['memory']
            )
        return self.output_object['memory']
    
    def match_svc_definition(self, memory_regs, svc_name):
        svc_file = os.path.join(
            self.svc_definition_dir,
            svc_name + '.json'
        )
        with open(svc_file) as f:
            svc_definitions = json.load(f)
            
        register = ARM_REG_R0
        stack_pointer = self.reg_eval.get_register_bytes(
            memory_regs['registers'],
            ARM_REG_SP,
            'int'
        )
        output_object = {
            'output': {},
            'memory': {}
        }
        for arg in svc_definitions['args']:
            val = self.reg_eval.get_register_bytes(
                memory_regs['registers'],
                register
            )
            if val == None: val = '00000000'
            logging.debug(
                'Read value '
                + str(val)
                + ' from register: '
                + str(register)
            )
            register += 1
            # Process the value, according to the definition.
            output_object = self.process_argument(
                svc_definitions['args'][arg],
                memory_regs,
                val,
                output_object
            )
        return output_object
            
    def process_argument(self, arg_definition, memory_regs, val, output_object):
        # If output.
        if arg_definition['in_out'] == 'out':
            mem_address = val
            if 'memory_offset' in arg_definition:
                mem_address += arg_definition['memory_offset']
            output_object = self.process_output(
                arg_definition,
                mem_address,
                output_object
            )
            return output_object

        # Process the value according to data structure.
        data_structure = arg_definition['data']
        structured_data = {}
        
        if arg_definition['ptr_val'] == 'pointer':
            mem_address = int(val, 16)
            if 'memory_offset' in arg_definition:
                mem_address += arg_definition['memory_offset']
            structured_data = self.process_pointer_data(
                data_structure,
                memory_regs,
                mem_address,
                structured_data
            )
        else:
            value = self.convert_to_bit_string(val)
            structured_data = self.process_value_data(
                data_structure,
                memory_regs,
                value,
                structured_data
            )

        # Assign to output object.
        for key in structured_data:
            output_object['output'][key] = structured_data[key]
            
        # If custom output:
        # Note that this is different to just "out"! This has input AND output.
        # We also ignore any memory offset.
        if 'out' in arg_definition['in_out']:
            mem_address = val
            output_object = self.process_output(
                arg_definition,
                mem_address,
                output_object
            )
        return output_object
    
    def process_value_data(self, data_structure, memory_regs, value_in_bits, current_object):
        logging.debug(
            'Start Process Value Data , with starting bits: ' 
            + value_in_bits
        )
        structured_data = {}
        if (len(list(data_structure.keys())) == 1):
            arg_name = list(data_structure.keys())[0]
            logging.debug(
                'Single element structure for '
                + arg_name
                + ' with bits: '
                + value_in_bits
            )
            element = self.format_element(
                data_structure[arg_name],
                memory_regs,
                value_in_bits,
                current_object
            )
            structured_data[arg_name] = element
            return structured_data
            
        # If there is more than one key, then further processing is needed.
        for structure_element in data_structure:
            logging.debug(
                'Analysing ' 
                + structure_element 
                + ' in value mode, with starting bits: '
                + value_in_bits
            )
            structured_data[structure_element] = self.process_value_element(
                data_structure[structure_element],
                memory_regs,
                value_in_bits,
                structured_data
            )
            # Update bitstring.
            if data_structure[structure_element]['ptr_val'] == 'pointer':
                len_bits = 32
            else:
                len_bits = self.get_length_field(
                    data_structure[structure_element],
                    structured_data
                )
            value_in_bits = value_in_bits[len_bits:]
            
        return structured_data
        
    def process_value_element(self, data_structure, memory_regs, value_in_bits, current_object):
        if data_structure['ptr_val'] == 'pointer':
            address = int(value_in_bits[0:32], 2)
            structured_data = self.process_pointer_data(
                data_structure,
                memory_regs,
                address,
                current_object
            )
        else:
            len_bits = self.get_length_field(
                data_structure,
                current_object
            )
            element_bits = value_in_bits[0:len_bits]
            if len(element_bits) < len_bits:
                logging.error('Incorrect number of bits! ' + element_bits)
            structured_data = self.format_element(
                data_structure,
                memory_regs,
                element_bits,
                current_object
            )
        return structured_data
        
    def process_pointer_data(self, data_structure, memory_regs, mem_address, current_object):
        logging.debug(
            'Start Process Pointer Data , with starting address: ' 
            + hex(mem_address)
        )
        structured_data = {}
        for structure_element in data_structure:
            logging.debug(
                'Analysing ' 
                + structure_element 
                + ' in pointer mode, with address:'
                + hex(mem_address)
            )
            
            # Get offset for next address.
            if data_structure[structure_element]['ptr_val'] == 'pointer':
                offset = 4
                # Addresses must be word-aligned.
                modulo_remainder = mem_address % 4
                mem_address += modulo_remainder
            else:
                len_bits = self.get_length_field(
                    data_structure[structure_element],
                    current_object
                )
                offset = int(len_bits/8)
            
            # Process according to different types.
            structured_data[structure_element] = self.process_pointer_element(
                data_structure[structure_element],
                memory_regs,
                mem_address,
                structured_data
            )
            
            # Compute next address.
            mem_address += offset
            
        return structured_data
        
    def process_pointer_element(self, data_structure, memory_regs, mem_address, current_object):
        # We consider 4 cases: 
        if ((data_structure['ptr_val'] == 'value') 
                and (data_structure['type'] != 'dict')):
            structured_data = self.process_pointer_value_nondictionary(
                data_structure,
                memory_regs,
                mem_address,
                current_object
            )
        elif ((data_structure['ptr_val'] == 'value') 
                and (data_structure['type'] == 'dict')):
            structured_data = self.process_pointer_value_dictionary(
                data_structure['data'],
                memory_regs,
                mem_address,
                current_object
            )
        elif ((data_structure['ptr_val'] == 'pointer') 
                and (data_structure['type'] != 'dict')):
            structured_data = self.process_pointer_pointer_nondictionary(
                data_structure,
                memory_regs,
                mem_address,
                current_object
            )
        else:
            structured_data = self.process_pointer_pointer_dictionary(
                data_structure['data'],
                memory_regs,
                mem_address,
                current_object
            )
        return structured_data
            
    def process_pointer_value_nondictionary(self, data_structure, memory_regs, mem_address, current_object):
        # Just read bits and format.
        len_bits = self.get_length_field(
            data_structure,
            current_object
        )
        num_bytes = int(len_bits/8)
        
        if 'byte-endian' in data_structure:
            byte_endianness = data_structure['byte-endian']
        else:
            byte_endianness = None
        value = self.get_data_from_memory(
            memory_regs,
            mem_address,
            num_bytes,
            byte_endianness
        )
        # Convert to bits.
        value_in_bits = self.convert_to_bit_string(value)
        element = self.format_element(
            data_structure,
            memory_regs,
            value_in_bits,
            current_object
        )
        return element
        
    def process_pointer_value_dictionary(self, data_structure, memory_regs, mem_address, current_object):
        element = self.process_pointer_data(
            data_structure,
            memory_regs,
            mem_address,
            current_object
        )
        return element
        
    def process_pointer_pointer_nondictionary(self, data_structure, memory_regs, mem_address, current_object):
        # Get address (from memory).
        address_value = self.get_data_from_memory(
            memory_regs,
            mem_address,
            4
        )
        new_address = int(address_value, 16)

        # Read from new address in memory.
        len_bits = self.get_length_field(
            data_structure,
            current_object
        )
        num_bytes = int(len_bits/8)
        if 'byte-endian' in data_structure:
            byte_endianness = data_structure['byte-endian']
        else:
            byte_endianness = None
        value = self.get_data_from_memory(
            memory_regs,
            new_address,
            num_bytes,
            byte_endianness
        )
        
        # Convert to bits.
        value_in_bits = self.convert_to_bit_string(value)
        
        # Format
        element = self.format_element(
            data_structure,
            memory_regs,
            value_in_bits,
            current_object
        )
        return element
        
    def process_pointer_pointer_dictionary(self, data_structure, memory_regs, mem_address, current_object):
        # Get address from memory.
        address_value = self.get_data_from_memory(
            memory_regs,
            mem_address,
            4
        )
        new_address = int(address_value, 16)
        
        # Pass to normal processing?
        element = self.process_pointer_data(
            data_structure,
            memory_regs,
            new_address,
            current_object
        )
        return element
    
    def get_data_from_memory(self, memory_regs, mem_address, num_bytes, 
                endian=common_objs.endian):
        logging.debug(
            'Reading '
            + str(num_bytes)
            + ' from memory address: '
            + hex(mem_address)
        )
        if num_bytes == 0: return ''
        address_type = self.reg_eval.get_address_type(
            mem_address,
            memory_regs['memory']
        )
        if address_type == consts.ADDRESS_FIRMWARE:
            value = self.reg_eval.get_firmware_bytes(
                mem_address,
                num_bytes,
                'hex',
                endian
            )
            return value
        if address_type == consts.ADDRESS_DATA:
            value = self.reg_eval.get_data_bytes(
                mem_address,
                num_bytes,
                'hex',
                endian
            )
            return value
        value = ''           
        if (num_bytes%4 == 0):
            num_words = int(num_bytes/4)
            for i in range(num_words):
                read_word = self.get_memory_bytes(
                    memory_regs['memory'],
                    mem_address+4*i,
                    4,
                    endian
                )
                if ((read_word == None) or (read_word == '')):
                    read_word = '00000000'
                value += read_word
        else:
            value = self.get_memory_bytes(
                memory_regs['memory'],
                mem_address,
                num_bytes,
                endian
            )
        if ((value == None) or (value == '')):
            value = ''.zfill(num_bytes * 2)
        if len(value) < (num_bytes*2):
            diff = (num_bytes*2) - len(value)
            for i in range(diff):
                value += '0'
        return value
        
    def get_memory_bytes(self, memory_map, address, num_bytes=4, endian=common_objs.endian):
        if ((num_bytes == 4) and (address%4 == 0)):
            logging.debug('Getting memory word.')
            value = self.reg_eval.get_memory_word(memory_map, address, endian)
        elif ((num_bytes == 2) and (address%2 == 0)):
            logging.debug('Getting memory half-word.')
            value = self.reg_eval.get_memory_halfword(memory_map, address, endian)
        else:
            logging.debug('Getting memory bytes.')
            remaining_bytes = num_bytes
            value = ''
            while remaining_bytes > 0:
                if address not in memory_map:
                    value += '00'
                else:
                    value += memory_map[address]
                address += 1
                remaining_bytes -= 1
        if ((value == None) or (value == '')):
            value = ''.zfill(num_bytes * 2)
        return value
        
    def process_bitfield_data(self, data_structure, memory_regs, value_in_bits, current_object):
        structured_data = {}
        first_level_keys = list(data_structure.keys())
        for first_level_key in first_level_keys:
            len_bits = self.get_length_field(
                data_structure[first_level_key],
                current_object
            )
            element_bits = value_in_bits[0:len_bits]
            value_in_bits = value_in_bits[len_bits:]
            if data_structure[first_level_key]['type'] == 'dict':
                structured_data[first_level_key] = self.process_value_data(
                    data_structure[first_level_key]['data'],
                    memory_regs,
                    element_bits,
                    structured_data
                )
            elif data_structure[first_level_key]['type'] == 'bitfield':
                structured_data[first_level_key] = self.process_bitfield_data(
                    data_structure[first_level_key]['data'],
                    memory_regs,
                    element_bits,
                    structured_data
                )
            else:
                structured_data[first_level_key] = self.format_element(
                    data_structure[first_level_key],
                    memory_regs,
                    element_bits,
                    structured_data
                )
        return structured_data
        
    def get_length_field(self, data_structure, current_object):
        length_bits = data_structure['length_bits']
        if type(length_bits) is int:
            return length_bits
        
        split_pattern = length_bits.split(' ')
        arithmetic_function = []
        for element in split_pattern:
            element = element.strip()
            if element in ['*', '+', '-']:
                arithmetic_function.append(element)
            elif element.isdigit():
                arithmetic_function.append(int(element))
            else:
                element_value = self.get_previously_processed_data(
                    element,
                    current_object
                )
                arithmetic_function.append(int(element_value))
        
        if '*' in arithmetic_function:
            arithmetic_function.remove('*')
            output = arithmetic_function[0]
            for value in arithmetic_function[1:]:
                output = output * value
        elif '+' in arithmetic_function:
            arithmetic_function.remove('+')
            output = arithmetic_function[0]
            for value in arithmetic_function[1:]:
                output = output + value
        elif '-' in arithmetic_function:
            arithmetic_function.remove('-')
            output = arithmetic_function[0]
            for value in arithmetic_function[1:]:
                output = output - value
        return output
        
    def get_previously_processed_data(self, pattern, current_object):
        split_path = pattern.split('->')
        value_to_store = current_object
        for component in split_path:
            value_to_store = value_to_store[component]
        return value_to_store
    
    def format_element(self, format_structure, memory_regs, element_bits, current_object):
        if 'word-endian' in format_structure:
            element_bits = self.process_endianness(
                element_bits,
                format_structure['word-endian']
            )
        element = self.convert_element_type(
            format_structure,
            element_bits,
            memory_regs,
            current_object
        )
        return element
    
    def process_endianness(self, bitstring, endian):
        string_len = int(endian.split('-')[1])
        num_words = int(string_len/4)
        if endian.startswith('little'):
            converted_bits = ''.join(reversed([bitstring[i:i+string_len] 
                    for i in range(0, len(bitstring), string_len)]))
        else:
            converted_bits = bitstring
        return converted_bits
        
    def convert_element_type(self, element_structure, element_bits, memory_regs, current_object):
        len_bits = self.get_length_field(
            element_structure,
            current_object
        )
        if ((element_bits == None) or (element_bits == '')):
            return None
        dtype = element_structure['type']
        if dtype == 'hex':
            element_value = int(element_bits, 2)
            len_halfbytes = int(len_bits/4)
            element_value = '{0:0{1}x}'.format(element_value, len_halfbytes)
        elif dtype == 'int8':
            element_value = int(element_bits, 2)
            element_value = np.int8(element_value)
        elif dtype == 'uint8':
            element_value = int(element_bits, 2)
            element_value = np.uint8(element_value)
        elif dtype == 'int16':
            element_value = int(element_bits, 2)
            element_value = np.int16(element_value)
        elif dtype == 'uint16':
            element_value = int(element_bits, 2)
            element_value = np.uint16(element_value)
        elif dtype == 'int32':
            element_value = int(element_bits, 2)
            element_value = np.int32(element_value)
        elif dtype == 'uint32':
            element_value = int(element_bits, 2)
            element_value = np.uint32(element_value)
        elif dtype == 'dict':
            element_value = self.process_value_data(
                element_structure['data'],
                memory_regs,
                element_bits,
                current_object
            )
        elif dtype == 'bitfield':
            element_value = self.process_bitfield_data(
                element_structure['data'],
                memory_regs,
                element_bits,
                current_object
            )
            
        return element_value
        
    def update_memory(self, memory_object, ram_data):
        for address in ram_data:
            if ram_data[address] == None:
                continue
            if address not in memory_object:
                memory_object[address] = ram_data[address]
            else:
                if memory_object[address] != ram_data[address]:
                    logging.debug(
                        'Duplicate address: '
                        + hex(address)
                        + '. Existing value: '
                        + str(memory_object[address])
                        + '. New value: '
                        + str(ram_data[address])
                    )
                memory_object[address] = ram_data[address]
        return memory_object
        
    def process_output(self, arg_definition, val, output_object):
        logging.debug('Processing output object.')
        for arg_name in arg_definition['data']:
            if arg_definition['data'][arg_name]['type'] == 'dict':
                output_object = self.process_output(
                    arg_definition['data'][arg_name],
                    val,
                    output_object
                )
            else:
                address_bytes = val[0:8]
                mem_address = int(address_bytes, 16)
                if len(val) > 8: val = val[8:]
                output_definition = arg_definition['data'][arg_name]
                if output_definition['store_type'] == 'value':
                    value_to_store = output_definition['store']
                    output_object['memory'][mem_address] = value_to_store
                    logging.debug(
                        'Storing value '
                        + str(value_to_store) 
                        + ' to memory address: '
                        + hex(mem_address)
                    )
                elif output_definition['store_type'] == 'random':
                    num_random_bits = self.get_length_field(
                        output_definition,
                        output_object
                    )
                    num_hex_chars = int(num_random_bits/4)
                    value_to_store = hex(getrandbits(num_random_bits))[2:]
                    # Don't allow all-0 random number.
                    while value_to_store.replace('0', '').strip() == '':
                        value_to_store = hex(getrandbits(num_random_bits))[2:]
                    value_to_store = value_to_store.zfill(num_hex_chars)
                    output_object['memory'][mem_address] = value_to_store
                    logging.debug(
                        'Storing value '
                        + str(value_to_store) 
                        + ' to memory address: '
                        + hex(mem_address)
                    )
                else:
                    value_to_store = output_definition['store']
                    if '->' in value_to_store:
                        value_to_store = self.get_previously_processed_data(
                            value_to_store,
                            output_object
                        )
                    output_object['memory'][mem_address] = value_to_store
                    logging.debug(
                        'Storing value '
                        + str(value_to_store) 
                        + ' to memory address: '
                        + hex(mem_address)
                    )
                if output_definition['output'] == True:
                    output_object['output'][arg_name] = value_to_store
        return output_object
        
    def convert_to_bit_string(self, value):
        if value == None: return value
        if value == '': return value
        if type(value) is str:
            value = bin(int('1'+value, 16))[3:]
        else:
            value = bin(value)[2:]
        return value