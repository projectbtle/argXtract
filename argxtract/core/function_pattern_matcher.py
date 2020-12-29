import os
import sys
import copy
import json
import random
import logging
import numpy as np
from capstone import *
from capstone.arm import *
from operator import itemgetter, getitem 
from argxtract.common import paths as common_paths
from argxtract.core import utils
from argxtract.core import consts
from argxtract.common import objects as common_objs
from argxtract.core.strand_execution import StrandExecution

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
# Turn on SKIPDATA mode - this is needed!
md.skipdata = True
md.detail = True


class FunctionPatternMatcher:
    def __init__(self):
        self.test_sets = {}
        self.interrupt_handlers = []
        for itrpt in common_objs.application_vector_table:
            if itrpt in ['initial_sp', 'systick']: continue
            self.interrupt_handlers.append(
                common_objs.application_vector_table[itrpt]
            )
        
    def match_vendor_functions(self):
        logging.info('Performing vendor function pattern matching.')
        matched_functions = {}
        
        vendor_dir = os.path.join(
            common_paths.vendor_path,
            'fpfs'
        )
        pattern_files = []
        for root, dirs, filenames in os.walk(vendor_dir):
            for filename in filenames:
                if filename.endswith('.json'):
                    pattern_files.append(os.path.join(root, filename))
                    
        if pattern_files == []:
            logging.error('No function pattern files found!')
            return
        
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        self.all_addresses = all_addresses
        
        for pattern_file in pattern_files:
            logging.debug(
                'Testing against pattern file '
                + pattern_file
            )
            self.load_test_set(pattern_file)
            if self.test_sets == {}:
                continue
                
            filename = \
                (os.path.basename(pattern_file)).replace('.json', '')
            address = self.match_pattern_file(
                pattern_file
            )
            if address != None:
                matched_functions[filename] = {}
                matched_functions[filename]['function_address'] = address
                callers = common_objs.function_blocks[address]['xref_from']
                matched_functions[filename]['callers'] = callers
                
        return matched_functions

    def load_test_set(self, pattern_file):
        try:
            with open(pattern_file) as f:
                json_file = json.load(f)
        except:
            logging.warning(
                'Errored JSON file: '
                + pattern_file
            )
            self.test_sets = {}
            return
        
        if 'test_sets' not in json_file:
            logging.warning(
                'No test sets provided: '
                + pattern_file
            )
            self.test_sets = {}
            return
            
        for key in json_file['test_sets']:
            self.test_sets[key] = json_file['test_sets'][key]
            
    def match_pattern_file(self, pattern_file):
        # Check each function for pattern match.
        matches = []
        sorted_functions = {k: v for k, v in sorted(common_objs.function_blocks.items(), 
                key = lambda x: getitem(x[1], 'call_depth'))}
        for function in sorted_functions:
            to_check = True
            # If one function matches, then don't consider its callers.
            # They would automatically match?
            for match in matches:
                if match in common_objs.function_blocks[function]['xref_to']:
                    to_check = False
                    break
            if to_check == False:
                continue
            is_match = self.match_function_to_pattern(
                function
            )
            if is_match == True:
                matches.append(function)
        if matches == []:
            logging.warning('No pattern matches for ' + pattern_file)
            return None
        
        if len(matches) > 1:
            logging.warning(
                'More than one pattern match for ' 
                + pattern_file
                + ': '
                + str(matches)
            )
            return None
            
        match = matches[0]
        logging.info(
            'Function at '
            + hex(match)
            + ' matches '
            + pattern_file
        )
        return match
        
    def match_function_to_pattern(self, start_address):
        end_address = utils.id_function_block_end(start_address)
        
        has_unsupported_operations = self.unsupported_operations(
            start_address, 
            end_address
        )
        if has_unsupported_operations == True:
            return False
  
        is_match = self.analyse_function(
            start_address, 
            end_address
        )
        return is_match

    def unsupported_operations(self, function_start, function_end):    
        # If the function has no callers, we won't be able to trace.
        if common_objs.function_blocks[function_start]['xref_from'] == []:
            return True
        
        # If the function is denylisted, don't analyse.
        if function_start in common_objs.denylisted_functions:
            return True

        # If the function is an interrupt handler, then exclude.
        if function_start in self.interrupt_handlers:
            return True
            
        # We don't analyse functions with very high call depth.
        if common_objs.function_blocks[function_start]['call_depth'] > 25:
            return True
        
        # Large functions are not supported at present.        
        if ((function_end-function_start) > 300):
            # UNSUPPORTED returns TRUE
            return True
            
        return False
        
    def analyse_function(self, start_address, end_address):
        logging.trace(
            '\nAnalysing function starting at ' 
            + hex(start_address) 
            + ' for pattern match.'
        ) 

        exits = self.identify_exits(start_address, end_address)
        
        logging.debug('Comparing symbolic execution of function against pattern.')

        for test_set in self.test_sets:
            exec_output_object = self.symbolically_execute_test_set(
                start_address,
                exits,
                self.test_sets[test_set]['input']
            )
            logging.trace(
                'Function\'s symbolic execution output for test set '
                + str(test_set)
                + ': '
                + str(exec_output_object)        
            )
            pattern_memory_obj = self.test_sets[test_set]['output']['mem']
            function_memory_obj = exec_output_object['mem']
            if self.compare_memory_objects(test_set, pattern_memory_obj, function_memory_obj) == False:
                logging.trace(
                    'Memory contents don\'t match for test set '
                    + str(test_set)
                )
                return False
            pattern_register_obj = self.test_sets[test_set]['output']['reg']
            function_register_obj = exec_output_object['reg']
            if self.compare_register_objects(pattern_register_obj, function_register_obj) == False:
                logging.trace(
                    'Register contents don\'t match for test set '
                    + str(test_set)
                )
                return False
        return True
        
    def identify_exits(self, function_start, function_end):
        exits = [function_end]
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        
        address = function_start-2
        branch_identified = False
        while address < function_end:
            address = utils.get_next_address(all_addresses, address)
            if address == None: break
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                exits.append(address)
                continue
            insn = common_objs.disassembled_firmware[address]['insn']
            if insn == None:
                exits.append(address)
                continue
            if insn.id == 0:
                exits.append(address)
                continue
            if insn.id == ARM_INS_BX:
                exits.append(address)
                continue
            if insn.id == ARM_INS_POP:
                operands = insn.operands
                final_operand = operands[-1]
                if final_operand.value.reg == ARM_REG_PC:
                    exits.append(address)
                    continue
        return exits
        
    #======================= Execution =========================#
    def symbolically_execute_test_set(self, start_address, exits, test_set_input):
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        
        regs = {}
        for reg in test_set_input['reg']:
            for const_reg in consts.REGISTERS:
                if reg == consts.REGISTERS[const_reg]:
                    regs[const_reg] = test_set_input['reg'][reg]
                    break
        
        (strand_eval_obj, init_regs, condition_flags, current_path) = \
            self.initialise_objects_for_trace(
                all_addresses, 
                start_address, 
                regs
            )
        if strand_eval_obj == None:
            output_object = {
                'mem': {},
                'reg': {}
            }
            return output_object
            
        memory_map = {}
        for mem_key in test_set_input['mem']:
            mem_address = int(mem_key, 16)
            memory_map[mem_address] = test_set_input['mem'][mem_key]
            
        (pre_exec_address, memory_map, register_object) = \
            strand_eval_obj.trace_register_values(
                common_objs.disassembled_firmware,
                start_address,
                exits, 
                init_regs, memory_map, condition_flags, 
                False, False, True)
        output_object = {
            'mem': memory_map,
            'reg': register_object
        }
        return output_object
        
    def initialise_objects_for_trace(self, all_addresses, 
            trace_start, regs):
        strand_eval_obj = StrandExecution(
            all_addresses
        )
        # Initialise parameters.
        ## Initialise registers.
        init_regs = {}
        for reg in list(consts.REGISTERS.keys()):
            init_regs[reg] = None
            
        init_regs[ARM_REG_SP] = 'c0002000'
        pc_value = strand_eval_obj.get_pc_value(trace_start)
        if pc_value == None:
            if trace_start+4 in all_addresses:
                pc_value = trace_start+4
            elif trace_start+2 in all_addresses:
                pc_value = trace_start+2
            else:
                return (None, None, None, None)
        init_regs[ARM_REG_PC] = \
            '{0:08x}'.format(pc_value)
            
        for reg in regs:
            init_regs[reg] = regs[reg]
        
        ## Initialise path.
        current_path = hex(trace_start)
        ## Initialise condition flags.
        condition_flags = strand_eval_obj.initialise_condition_flags()
        
        return (strand_eval_obj, init_regs, condition_flags, current_path)
        
    #======================= Output checks =========================#
    def compare_memory_objects(self, test_set, pattern_memory_obj, function_memory_obj):
        if function_memory_obj == None:
            return False
        pattern_keys = list(pattern_memory_obj.keys())
        
        for pattern_key in pattern_keys:
            if pattern_key.startswith("group"):
                is_group_present = self.check_for_output_memory_block(
                    test_set,
                    function_memory_obj,
                    pattern_memory_obj[pattern_key]
                )
                if is_group_present == False:
                    return False
            else:
                if memory_address not in function_memory_obj:
                    logging.trace(
                        'Memory address ' 
                        + pattern_key 
                        + ' not present in function execution output.'
                    )
                    return False
                if (pattern_memory_obj[pattern_key] != 
                        function_memory_obj[memory_address]):
                    logging.trace(
                        'Value at memory address ' 
                        + pattern_key 
                        + ' doesn\'t match in function execution output.'
                    )
                    return False
        return True
                
    def check_for_output_memory_block(self, test_set, output_memory_object, 
            pattern_memory_group):
        is_present = False
        input_memory_addresses = []
        for key in self.test_sets[test_set]['input']['mem']:
            input_memory_addresses.append(
                int(key, 16)
            )
        
        offset_group = {}
        for key in pattern_memory_group['offset']:
            int_key = int(key)
            offset_group[int_key] = pattern_memory_group['offset'][key]
            
        for address in output_memory_object:
            if address in input_memory_addresses:
                continue
            if output_memory_object[address] != offset_group[0]:
                continue
            for offset in offset_group:
                if output_memory_object[address+offset] != offset_group[offset]:
                    break
                is_present = True
            
        return is_present
    
    def compare_register_objects(self, pattern_register_obj, function_register_obj):
        if function_register_obj == None:
            return False
        pattern_keys = list(pattern_register_obj.keys())
        for pattern_key in pattern_keys:
            register = None
            for const_reg in consts.REGISTERS:
                if pattern_key == consts.REGISTERS[const_reg]:
                    register = const_reg
            if register == None: continue
            
            if register not in function_register_obj:
                return False
                
            expected_values = pattern_register_obj[pattern_key]
            possible_values = []
            if "or" in expected_values:
                split_values = expected_values.split("or")
                for expected_value in split_values:
                    possible_values.append(expected_value.strip())
            else:
                possible_values.append(expected_values.strip())
            is_value_present = False
            for possible_value in possible_values:
                if (possible_value == function_register_obj[register]):
                    is_value_present = True
                
            if is_value_present == False:
                return False
        return True