import os
import sys
import copy
import json
import logging
from capstone import *
from capstone.arm import *
from argxtract.common import paths as common_paths
from argxtract.core import utils
from argxtract.core import consts
from argxtract.common import objects as common_objs

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
# Turn on SKIPDATA mode - this is needed!
md.skipdata = True
md.detail = True


class FunctionPatternMatcher:
    def __init__(self):
        pass
        
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
                if filename.endswith('.txt'):
                    pattern_files.append(os.path.join(root, filename))
                    
        if pattern_files == []:
            logging.error('No function pattern files found!')
            return
        
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        self.all_addresses = all_addresses
        
        for pattern_file in pattern_files:
            filename = \
                (os.path.basename(pattern_file)).replace('.txt', '')
            (pattern_insn_object, pattern_sections, pattern_registers) = \
                self.decompose_pattern_file(pattern_file)
            address = self.match_pattern_file(
                pattern_file,
                pattern_insn_object, 
                pattern_sections,
                pattern_registers
            )
            if address != None:
                if common_objs.function_blocks[address]['xref_from'] == []:
                    continue
                matched_functions[filename] = {}
                matched_functions[filename]['function_address'] = address
                callers = common_objs.function_blocks[address]['xref_from']
                matched_functions[filename]['callers'] = callers
                
        return matched_functions
                
    def decompose_pattern_file(self, pattern_file):
        logging.info('Matching pattern for ' + pattern_file)
        # The pattern file contains bytes corresponding to a function
        #  we want to match.
        with open(pattern_file) as f:
            pattern_file_bytes = f.read().strip()
        # Convert to bytes.
        pattern_file_bytes = bytes.fromhex(pattern_file_bytes) 
        # Disassemble.
        pattern_instructions = md.disasm(
            pattern_file_bytes,
            0x00000000
        )
        # Create a dictionary object with the pattern instructions,
        #  so that the same analyses can be applied to the pattern
        #  as for the firmware file's functions.
        trace_msg = ''
        pattern_insn_object = {}
        for instruction in pattern_instructions:
            pattern_insn_object[instruction.address] = {
                'insn': instruction,
                'is_data': False
            }
            trace_msg += '%s\t%s\t%s\n' %(instruction.address,
                                            instruction.mnemonic,
                                            instruction.op_str)
        logging.debug('Pattern instructions:\n' + trace_msg + '\n')
        pattern_instructions = None
        pattern_file_bytes = None
        
        # Decompose the pattern into sections.
        pattern_keys = list(pattern_insn_object.keys())
        pattern_keys.sort()
        pattern_start_address = pattern_keys[0]
        pattern_end_address = pattern_keys[-1]
        pattern_keys = None
        # Dummy key, to allow get_next_address to work.
        pattern_insn_object[-2] = {
            'insn': None,
            'is_data': False
        }
        pattern_sections = self.function_decompose(
            pattern_start_address, 
            pattern_end_address,
            pattern_insn_object
        )

        # Identify input registers used in pattern function.
        pattern_registers = self.identify_input_registers(
            pattern_sections,
            pattern_insn_object
        )
        pattern_registers.sort()
        logging.debug('Pattern registers ' + str(pattern_registers))
        
        return (pattern_insn_object, pattern_sections, pattern_registers)
        
    def match_pattern_file(self, pattern_file, pattern_insn_object, 
            pattern_sections, pattern_registers):
        # Check each function for pattern match.
        matches = []
        for function in common_objs.function_blocks:
            is_match = self.match_function_to_pattern(
                function, 
                pattern_insn_object,
                pattern_sections,
                pattern_registers
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
        logging.debug(
            'Function at '
            + hex(match)
            + ' matches '
            + pattern_file
        )
        return match
        
    def match_function_to_pattern(self, start_address, pattern_insn_object,
            pattern_sections, pattern_registers):
        end_address = utils.id_function_block_end(start_address)
        
        has_unsupported_operations = self.unsupported_operations(
            start_address, 
            end_address, 
            common_objs.disassembled_firmware
        )
        if has_unsupported_operations == True:
            return False
  
        is_match = self.analyse_function(
            start_address, 
            end_address, 
            pattern_insn_object,
            pattern_sections,
            pattern_registers
        )
        return is_match

    def unsupported_operations(self, function_start, function_end, function_object):
        # There are many operations we don't support in this first attempt.
        
        # Large functions are excluded.        
        if ((function_end-function_start) > 20):
            # UNSUPPORTED returns TRUE
            return True
            
        # We don't support more than one conditional operation.
        num_conditionals = 0
        address = function_start-2
        while address <= function_end:
            address = utils.get_next_address(self.all_addresses, address)
            if address == None: break
            
            insn = function_object[address]['insn']
            if insn == None: continue
            
            if insn.id in [ARM_INS_CBNZ, ARM_INS_CBZ]:
                num_conditionals += 1
            elif ((insn.id == ARM_INS_B) 
                    and (insn.cc != ARM_CC_AL) 
                    and (insn.cc != ARM_CC_INVALID)):
                num_conditionals += 1
            elif insn.id == ARM_INS_BL:
                # We don't support external function calls.
                # UNSUPPORTED returns TRUE
                return True
                
        if num_conditionals > 1:
            # UNSUPPORTED returns TRUE
            return True
    
    def analyse_function(self, start_address, end_address, 
            pattern_insn_object, pattern_sections, pattern_registers):
        logging.debug(
            '\nAnalysing function starting at ' 
            + hex(start_address) 
            + ' for pattern match.'
        ) 
        
        # First see if basic components are present.
        # That is, some elements like STR must be present in both compared
        #  functions for them to match.
        is_basic_match = self.compare_basic_components(
            start_address, 
            end_address, 
            pattern_insn_object
        )
        if is_basic_match == False: return False
        
        # Decompose the function into basic blocks.
        function_sections = self.function_decompose(
            start_address,
            end_address,
            common_objs.disassembled_firmware
        )
        
        # Compare the registers used to hold inputs.
        # Input registers in function.
        input_registers = self.identify_input_registers(
            function_sections,
            common_objs.disassembled_firmware
        )
        input_registers.sort()
        if pattern_registers != input_registers:
            logging.debug('Input registers don\'t match')
            return False
        
        logging.debug('Pattern sections\n' + json.dumps(pattern_sections))
        logging.debug('Function sections\n' + json.dumps(function_sections))
        
        # Compare with the given pattern.
        is_branch_in_pattern = False
        if len(pattern_sections['branch']['address']) > 0: 
            is_branch_in_pattern = True
        is_branch_in_function = False
        if len(function_sections['branch']['address']) > 0: 
            is_branch_in_function = True
        if is_branch_in_function != is_branch_in_pattern:
            logging.debug('Only one (pattern or function) has branch. No match.')
            return False

        if is_branch_in_function == True:
            (pattern_comp_reg, pattern_comp_value, pattern_comp_cc) = \
                self.get_comparison_reg_value(
                    pattern_sections,
                    pattern_insn_object
                )
            (function_comp_reg, function_comp_value, function_comp_cc) = \
                self.get_comparison_reg_value(
                    function_sections,
                    common_objs.disassembled_firmware
                )

            if pattern_comp_reg != function_comp_reg:
                logging.debug('Comparison registers don\'t match.')
                return False
            if pattern_comp_value != pattern_comp_value:
                logging.debug('Comparison values don\'t match.')
                return False
            condition_match = self.check_condition_match(
                function_comp_cc,
                pattern_comp_cc
            )
            if condition_match not in [1, -1]:
                logging.debug('Comparison conditions don\'t match.')
                return False
        
        is_match = self.compare_function_with_pattern(
            function_sections,
            pattern_insn_object,
            pattern_sections,
            condition_match
        )
        
        return is_match
    
    def check_condition_match(self, function_cc, pattern_cc):
        if function_cc == pattern_cc:
            return 1
        if abs(function_cc - pattern_cc) != 1:
            return 0
        if ((function_cc % 2) == 1):
            function_cc += 1
        if ((pattern_cc % 2) == 1):
            pattern_cc += 1
        if function_cc != pattern_cc:
            return 0
        return -1
        
    
    def compare_basic_components(self, start_address, end_address, 
            pattern_insn_object):
        function_basics = self.check_basic_components_for_function(
            start_address,
            end_address,
            common_objs.disassembled_firmware
        )
        pattern_addresses = list(pattern_insn_object.keys())
        pattern_addresses.sort()
        pattern_end_address = pattern_addresses[-1]
        pattern_basics = self.check_basic_components_for_function(
            0x00000000,
            pattern_end_address,
            pattern_insn_object
        )
        if function_basics != pattern_basics:
            logging.debug('Basic components don\'t match.')
            return False
        return True
        
    def check_basic_components_for_function(self, start, end, function_object):
        components = {
            'str': False
        }
        all_addresses = list(function_object.keys())
        all_addresses.sort()
        address = start-2
        while address <= end:
            address = utils.get_next_address(all_addresses, address)
            if address == None: break
            insn = function_object[address]['insn']
            if insn == None: continue
            
            if (insn.id in [ARM_INS_STR, ARM_INS_STRB, ARM_INS_STREX, 
                    ARM_INS_STREXB, ARM_INS_STREXH, ARM_INS_STRH]):
                components['str'] = True
        return components
    
    def get_comparison_reg_value(self, sections, function_object):
        path = sections['pre-branch'] + sections['branch']['address']
        
        comparison_reg = None
        comparison_value = None
        comparison_condition = sections['branch']['condition']
        
        processed_register_path = self.get_equivalent_regs_for_path(
            path,
            function_object
        )
        comparison_address = sections['branch']['address'][0]
        original_comparison_insn = function_object[comparison_address]['insn']
        original_comparison_reg = original_comparison_insn.operands[0].value.reg
        comparison_reg = processed_register_path[comparison_address]['dst_reg']
        comparison_value = processed_register_path[comparison_address]['dst_val']
        
        if original_comparison_insn.id in [ARM_INS_CBNZ, ARM_INS_CBZ]:
            comparison_type = 'imm'
        else:
            comparison_type = 'reg'
        
        return (comparison_reg, comparison_value, comparison_condition)
        
    def get_equivalent_regs_for_path(self, path, function_object):
        logging.debug('Generating equivalent register path.')
        new_path = {}
        regs = {}
        for reg in [ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3]:
            regs[reg] = 'reg' + str(reg)
            
        for address in path:
            new_path[address] = {
                'opcode': None,
                'dst_reg': None,
                'dst_val': None
            }
            if function_object[address]['is_data'] == True: continue
            insn = function_object[address]['insn']
            if insn == None: continue
            if insn.id == ARM_INS_INVALID: continue
            operands = insn.operands
            
            new_path[address]['opcode'] = insn.id
            
            # Some instructions need not be analysed.
            if (insn.id in [ARM_INS_PUSH, ARM_INS_POP, ARM_INS_B, ARM_INS_BL,
                    ARM_INS_BX, ARM_INS_INVALID]):
                continue
            
            if len(operands) == 0:
                continue
                
            new_path[address]['dst_reg'] = operands[0].value.reg
            
            # With STR, we only care about the source register 
            #  (misleading named "dst_reg" :) )
            # No further processing is required.
            if (insn.id in [ARM_INS_STR, ARM_INS_STRB, ARM_INS_STREX, 
                    ARM_INS_STREXB, ARM_INS_STREXH, ARM_INS_STRH]):
                continue

            if len(operands) < 2:
                continue
                
            if (insn.id in [ARM_INS_MOV, ARM_INS_MOVW]):
                if operands[1].type == ARM_OP_REG:
                    new_path[address]['dst_val'] = regs[operands[1].value.reg]
                else:
                    new_path[address]['dst_val'] = 'imm' + str(operands[1].value.imm)
            elif (insn.id in [ARM_INS_LDR, ARM_INS_LDREX, 
                    ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH, 
                    ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB]):
                new_path[address]['dst_val'] = 'mem'
            elif (insn.id in [ARM_INS_CBZ, ARM_INS_CBNZ]):
                new_path[address]['dst_reg'] = regs[operands[0].value.reg]
                new_path[address]['dst_val'] = 'imm0'
            elif (insn.id in [ARM_INS_CMN, 
                    ARM_INS_CMP, ARM_INS_TEQ, ARM_INS_TST]):
                new_path[address]['dst_reg'] = regs[operands[0].value.reg]
                if operands[1].type == ARM_OP_REG:
                    new_path[address]['dst_val'] = regs[operands[1].value.reg]
                else:
                    new_path[address]['dst_val'] = 'imm' + str(operands[1].value.imm)
            else:
                dst_value = None
                for idx, operand in enumerate(reversed(operands)):
                    if idx == (len(operands)-1):
                        break
                    if operand.type == ARM_OP_REG:
                        if operand.value.reg == new_path[address]['dst_reg']:
                            continue
                        if dst_value == None:
                            dst_value = regs[operand.value.reg]
                        else:
                            if regs[operand.value.reg] in dst_value:
                                continue
                            dst_value = 'proc'
                    elif operand.type == ARM_OP_IMM:
                        if dst_value == None:
                            dst_value = 'imm' + str(operand.value.imm)
                        else:
                            dst_value = 'proc'
                            
            # Update reg object.
            # Comparison functions don't modify regs.
            if (insn.id not in [ARM_INS_CBNZ, ARM_INS_CBZ, ARM_INS_CMN, 
                    ARM_INS_CMP, ARM_INS_TEQ, ARM_INS_TST]):
                regs[operands[0].value.reg] = new_path[address]['dst_val']

        return new_path
    
    def function_decompose(self, start_address, end_address, function_object):
        # Split the function into 3 sections:
        #  1. Instructions preceding conditional branch (if branch exists)
        #  2. Branch 1
        #  3. Branch 2
        sections = {
            'pre-branch': [],
            'branch': {
                'address': [],
                'target': None,
                'register': None,
                'value': None,
                'condition': None
            },
            'branch-path1': [],
            'branch-path2': []
        }
        
        # First get all instruction preceding any branch.
        sections = self.identify_prebranch(
            start_address, 
            end_address, 
            sections, 
            function_object
        )
        
        path1 = []
        path2 = []
        all_addresses = list(function_object.keys())
        all_addresses.sort()
        # If there was a branch, then get the two paths.
        if sections['branch']['address'] != []:
            # One of the two paths will begin at address immediately following branch.
            path1_address = utils.get_next_address(
                all_addresses,
                max(sections['branch']['address'])
            )
            path1 = self.trace_branch_paths(
                start_address,
                end_address,
                path1_address,
                sections['branch']['address'],
                function_object
            )
            # The other address will be the branch target.
            path2_address = sections['branch']['target']
            path2 = self.trace_branch_paths(
                start_address,
                end_address,
                path2_address,
                sections['branch']['address'],
                function_object
            )

        sections['branch-path1'] = path1
        sections['branch-path2'] = path2
        
        return sections
        
    def identify_prebranch(self, function_start, function_end, sections, function_object):
        all_addresses = list(function_object.keys())
        all_addresses.sort()
        
        address = function_start-2
        branch_identified = False
        while address <= function_end:
            address = utils.get_next_address(all_addresses, address)
            if address == None: break
            insn = function_object[address]['insn']
            if insn == None:
                address = utils.get_next_address(all_addresses, address)
                if address == None: break
                continue
            if insn.id == ARM_INS_INVALID:
                address = utils.get_next_address(all_addresses, address)
                if address == None: break
                continue

            operands = insn.operands
            if insn.id in [ARM_INS_CBNZ, ARM_INS_CBZ]:
                branch_target = operands[1].value.imm
                if ((branch_target < function_start) 
                        or (branch_target > function_end)):
                    return sections
                branch_identified = True
                sections['branch']['address'].append(address)
                sections['branch']['value'] = 0
                if insn.id == ARM_INS_CBZ:
                    sections['branch']['condition'] = ARM_CC_EQ
                else:
                    sections['branch']['condition'] = ARM_CC_NE
            elif (insn.id in [ARM_INS_CMN, 
                    ARM_INS_CMP, ARM_INS_TEQ, ARM_INS_TST]):
                orig_address = address
                address = \
                    utils.get_next_address(all_addresses, address)
                branch_insn = \
                    function_object[address]['insn']
                if branch_insn == None:
                    return sections
                if ((branch_insn.id != ARM_INS_B) 
                        or (branch_insn.cc == ARM_CC_AL) 
                        or (branch_insn.cc == ARM_CC_INVALID)):
                    return sections
                branch_operands = branch_insn.operands
                branch_target = branch_operands[0].value.imm
                if ((branch_target < function_start) 
                        or (branch_target > function_end)):
                    return sections
                sections['branch']['address'].append(orig_address)
                sections['branch']['address'].append(address)
                sections['branch']['condition'] = branch_insn.cc
                branch_identified = True
            if branch_identified == False:
                sections['pre-branch'].append(address)
            else:
                sections['branch']['target'] = branch_target
                break
        return sections
        
    def trace_branch_paths(self, function_start, function_end, 
            trace_start, conditional_branch_address, function_object):
        all_addresses = list(function_object.keys())
        all_addresses.sort()
        address = trace_start
        path = []
        while address <= function_end:
            path.append(address)
            if address in conditional_branch_address:
                break
            insn = function_object[address]['insn']
            if insn != None:
                if self.is_exit_instruction(insn) == True:
                    break
            if ((insn.id == ARM_INS_B) and (insn.cc == ARM_CC_AL)):
                branch_target = insn.operands[0].value.imm
                if address == branch_target: break
                address = branch_target
            else:
                address = utils.get_next_address(all_addresses, address)
        return path
        
    def is_exit_instruction(self, insn):
        if insn.id == ARM_INS_BX:
            return True
        if insn.id == ARM_INS_POP:
            operands = insn.operands
            final_operand = operands[-1]
            if final_operand.value.reg == ARM_REG_PC:
                return True
        return False
        
    def identify_input_registers(self, sections, function_object):
        paths = self.combine_paths(sections)
            
        input_registers = []
        non_input_registers = []
        for path in paths:
            (input_regs, non_input_regs) = \
                self.identify_input_registers_for_path(path, function_object)
            for non_input_reg in non_input_regs:
                if non_input_reg == 0: continue
                if non_input_reg not in non_input_registers:
                    non_input_registers.append(non_input_reg)
            for input_reg in input_regs:
                if input_reg == 0: continue
                if input_reg in non_input_registers: continue
                if input_reg not in input_registers:
                    input_registers.append(input_reg)
                    
        logging.debug('Input registers ' + str(input_registers))
        return input_registers
            
    def combine_paths(self, sections):
        paths = []
        if sections['branch']['address'] != []:
            path1_full = sections['pre-branch'] \
                         + sections['branch']['address'] \
                         + sections['branch-path1']
            path2_full = sections['pre-branch'] \
                         + sections['branch']['address'] \
                         + sections['branch-path2']
            paths = [path1_full, path2_full]
        else:
            paths = [sections['pre-branch']]
        return paths
        
    def identify_input_registers_for_path(self, path, function_object):
        input_regs = []
        non_input_regs = []
        for address in path:
            if function_object[address]['is_data'] == True:
                continue
            insn = function_object[address]['insn']
            if insn == None: continue
            
            # Some instructions don't have or shouldn't
            #  impact the registers.
            if insn.id in [ARM_INS_B, ARM_INS_BL, ARM_INS_INVALID]:
                continue
            if insn.id in [ARM_INS_MOV, ARM_INS_MOVW]:
                if insn.operands[0].value.reg == insn.operands[1].value.reg:
                    continue
            
            # Some instructions need special handling.
            operands = insn.operands
            if insn.id == ARM_INS_PUSH:
                for operand in operands:
                    if operand.type != ARM_OP_REG: continue
                    non_input_regs.append(operand.value.reg)
                continue
            elif insn.id in [ARM_INS_STR, ARM_INS_STREX, 
                    ARM_INS_STRH, ARM_INS_STREXH, 
                    ARM_INS_STRB, ARM_INS_STREXB,
                    ARM_INS_LDR, ARM_INS_LDREX, 
                    ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH, 
                    ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB]:
                input_regs = self.test_and_add_input_registers(
                    input_regs,
                    non_input_regs,
                    [operands[0], operands[1]]
                )
                continue
            elif insn.id in [ARM_INS_CMN, ARM_INS_CMP, ARM_INS_TEQ, 
                    ARM_INS_TST, ARM_INS_BX, ARM_INS_CBZ, ARM_INS_CBNZ]:
                cmp_regs = []
                for operand in operands:
                    cmp_regs.append(operand)
                input_regs = self.test_and_add_input_registers(
                    input_regs,
                    non_input_regs,
                    cmp_regs
                )
                continue

            if len(operands) == 0:
                continue

            # Apart from special instructions, we take 0th operand to be 
            #  destination operand and remaining as source operands.
            reg_operands = []
            for idx, operand in enumerate(reversed(operands)):
                if idx == (len(operands)-1):
                    break
                reg_operands.append(operand)
            input_regs = self.test_and_add_input_registers(
                input_regs,
                non_input_regs,
                reg_operands
            ) 
            if operands[0].value.reg not in input_regs:
                non_input_regs.append(operands[0].value.reg)
                
        return (input_regs, non_input_regs)  
        
    def test_and_add_input_registers(self, input_regs, non_input_regs, operands):
        all_regs = []
        for operand in operands:
            if operand.type == ARM_OP_REG:
                reg = operand.value.reg
                all_regs.append(reg)
            elif operand.type == ARM_OP_MEM:
                base_register = operand.value.mem.base
                index_register = operand.value.mem.index
                all_regs.append(base_register)
                all_regs.append(index_register)
                
        for reg in all_regs:
            if reg in [ARM_REG_INVALID, ARM_REG_PC, ARM_REG_SP, ARM_REG_LR]:
                continue
            if reg in non_input_regs:
                continue
            input_regs.append(reg)
        return input_regs
        
    def compare_function_with_pattern(self, function_sections, 
            pattern_insn_object, pattern_sections, condition_match):
        logging.debug('Analysing individual paths of function against pattern.')
        pattern_paths = self.combine_paths(pattern_sections)
        function_paths = self.combine_paths(function_sections)
        
        logging.debug('Mapping register values.')
        mapped_pattern_paths = []
        for pattern_path in pattern_paths:
            mapped_pattern_paths.append(
                self.get_equivalent_regs_for_path(
                    pattern_path,
                    pattern_insn_object
                )
            )
        
        mapped_function_paths = []
        for function_path in function_paths:
            mapped_function_paths.append(
                self.get_equivalent_regs_for_path(
                    function_path,
                    common_objs.disassembled_firmware
                )
            )
        
        logging.trace('Mapped pattern paths ' + str(mapped_pattern_paths))
        logging.trace('Mapped function paths ' + str(mapped_function_paths))
        
        num_paths = len(mapped_pattern_paths)
        if num_paths > 1:
            # If there's a branch, we need to check the condition
            (mapped_function_branch1, mapped_function_branch2) = \
                self.get_individual_branches(mapped_function_paths, function_sections)
            (mapped_pattern_branch1, mapped_pattern_branch2) = \
                self.get_individual_branches(mapped_pattern_paths, pattern_sections)
            if condition_match == 1:
                is_match = self.compare_function_path_with_pattern(
                    mapped_function_branch1,
                    mapped_pattern_branch1,
                    pattern_insn_object
                )
                if is_match == False: return False
                is_match = self.compare_function_path_with_pattern(
                    mapped_function_branch2,
                    mapped_pattern_branch2,
                    pattern_insn_object
                )
                if is_match == False: return False
            else:
                is_match = self.compare_function_path_with_pattern(
                    mapped_function_branch1,
                    mapped_pattern_branch2,
                    pattern_insn_object
                )
                if is_match == False: return False
                is_match = self.compare_function_path_with_pattern(
                    mapped_function_branch2,
                    mapped_pattern_branch1,
                    pattern_insn_object
                )
                if is_match == False: return False
        else:
            is_match = self.compare_function_path_with_pattern(
                mapped_function_paths[0],
                mapped_pattern_paths[0],
                pattern_insn_object
            )
            if is_match == False: return False
        return True
            
    def get_individual_branches(self, mapped_paths, sections):
        branch1_addresses = sections['branch-path1']
        branch2_addresses = sections['branch-path2']
        
        mapped_branch1_addresses = {}
        mapped_branch2_addresses = {}
        
        mapped_path1_keys = list(mapped_paths[0].keys())
        mapped_path2_keys = list(mapped_paths[1].keys())

        if ((set(branch1_addresses).issubset(set(mapped_path1_keys))) and 
                (set(branch2_addresses).issubset(set(mapped_path2_keys)))):
            path1 = mapped_paths[0]
            path2 = mapped_paths[1]
        elif ((set(branch1_addresses).issubset(set(mapped_path2_keys))) and 
                (set(branch2_addresses).issubset(set(mapped_path1_keys)))):
            path1 = mapped_paths[1]
            path2 = mapped_paths[0]
        else:
            logging.error('No matches for subset')
            path1 = {}
            path2 = {}
                
        for branch_address in path1:
            mapped_branch1_addresses[branch_address] = path1[branch_address]
        for branch_address in path2:
            mapped_branch2_addresses[branch_address] = path2[branch_address]
            
        return (mapped_branch1_addresses, mapped_branch2_addresses)
    
    def compare_function_path_with_pattern(self, function_path, pattern_path,
            pattern_insn_object):
        logging.debug(
            'Function path with equivalent registers: ' 
            + str(function_path)
            + '. Pattern path with equivalent registers: '
            + str(pattern_path)
        )
        # We first look for key instructions.
        address_matches = []
        address_mismatches = []
        for p_address in pattern_path:
            pattern_obj = pattern_path[p_address]
            pattern_insn = pattern_obj['opcode']
            if pattern_insn in [ARM_INS_STR, ARM_INS_STRB, ARM_INS_STREX, 
                    ARM_INS_STREXB, ARM_INS_STREXH, ARM_INS_STRH]:
                for f_address in function_path:
                    function_obj = function_path[f_address]
                    if function_obj['opcode'] != pattern_insn:
                        continue
                    if pattern_obj['dst_reg'] != function_obj['dst_reg']:
                        continue
                    if pattern_obj['dst_val'] != function_obj['dst_val']:
                        continue
                    address_matches.append(p_address)
                if p_address not in address_matches:
                    address_mismatches.append(p_address)
        
        if len(address_mismatches) > 0:
            logging.debug('Pattern mismatches identified.')
            return False
            
        # Consider final values of registers.
        p_regs = {}
        for p_address in pattern_path:
            pattern_obj = pattern_path[p_address]
            pattern_insn = pattern_obj['opcode']
            if pattern_insn in [ARM_INS_CMN, ARM_INS_CMP, ARM_INS_TEQ, ARM_INS_TST]:
                continue
            p_regs[pattern_obj['dst_reg']] = pattern_obj['dst_val']
        f_regs = {}
        for f_address in function_path:
            function_obj = function_path[f_address]
            function_insn = function_obj['opcode']
            if function_insn in [ARM_INS_CMN, ARM_INS_CMP, ARM_INS_TEQ, ARM_INS_TST]:
                continue
            f_regs[function_obj['dst_reg']] = function_obj['dst_val']
            
        logging.debug(
            'Final register values for pattern: '
            + str(p_regs)
            + ' and for function: '
            + str(f_regs)
        )
        # Register r0 typically contains an output code.
        # But what if it returns void?
        if ARM_REG_R0 in list(p_regs.keys()):
            if ARM_REG_R0 not in list(f_regs.keys()):
                return False
            if p_regs[ARM_REG_R0] != f_regs[ARM_REG_R0]:
                return False
        
        return True