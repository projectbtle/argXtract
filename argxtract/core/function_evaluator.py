import os
import sys
import copy
import logging
from capstone import *
from capstone.arm import *
from argxtract.common import paths as common_paths
from argxtract.core import utils
from argxtract.core import consts
from argxtract.common import objects as common_objs


class FunctionEvaluator:
    def __init__(self):
        pass
        
    def perform_function_block_analysis(self):
        logging.info(
            'Performing function block analyses.'
        )
        # Get all instruction addresses.
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        self.all_addresses = []
        for address in all_addresses:
            if address < common_objs.app_code_base:
                continue
            self.all_addresses.append(address)
        
        # Identify function blocks.
        self.find_function_blocks()
        
        # Identify important functions (like memset),
        #  which we will replace with equivalent functionality,
        #  to reduce processing time.
        self.identify_replace_functions()
        
        # Identify blacklisted blocks 
        #  (that should not be considered when tracing).
        # Functions we shouldn't branch to.
        self.populate_blacklist()
        
    def find_function_blocks(self):
        """Find potential function blocks within assembly code.
        
        This is a multi-step process: 
          Step 1(a): identify branch instructions that lead to "push" or "sub sp"
            instructions with high certainty. 
          Step 1(b): identify branch instructions that lead to "push" or "sub sp"
            instructions with less certainty. 
          Step 2: identify all "push" or "sub sp" instructions that may 
            indicate new function blocks that haven't been enumerated in 
            Step 1.
          Step 3: Create function block object.
        """
        
        function_block_start_addresses = []
        # Step 0.
        function_block_start_addresses = self.add_basic_functions(
            function_block_start_addresses
        )
        function_block_start_addresses.sort()
        
        # Step 1.
        function_block_start_addresses = self.check_branch_tos(
            function_block_start_addresses
        )
        function_block_start_addresses.sort()
        
        # Step 2.
        function_block_start_addresses = self.check_for_function_exit_ins(
            function_block_start_addresses
        )
        function_block_start_addresses.sort()

        # Create function block object.
        function_blocks = {}
        for idx, fb_start_address in enumerate(function_block_start_addresses):
            if fb_start_address < common_objs.code_start_address:
                continue
                
            if 'xref_from' not in common_objs.disassembled_firmware[fb_start_address]:
                xref_from = None
            else:
                xref_from = \
                    common_objs.disassembled_firmware[fb_start_address]['xref_from']
            
            if idx == len(function_block_start_addresses)-1:
                end = 'END'
            else:
                next_func_block_start = function_block_start_addresses[idx+1]
                end = next_func_block_start - 2
                
            function_blocks[fb_start_address] = {
                'end': end,
                'xref_from': xref_from,
                'xref_to': None,
                'call_depth': 0
            }
            
        logging.debug(
            'Identified '
            + str(len(list(function_blocks.keys())))
            + ' function blocks.'
        )
        if len(list(function_blocks.keys())) > 0:
            debug_msg = 'Function block starting addresses:\n'
            for item in function_blocks.keys():
                debug_msg += '\t\t\t\t' + hex(item) +'\n'
        logging.trace(debug_msg)
        common_objs.function_blocks = function_blocks

        # Populate xref to.
        # We do this after assigning previous to common_objs,
        #  in order to be able to utilise the id_function_block_for_instruction
        #  method from utils.
        logging.info('Getting xref tos')
        for fb_start_address in function_blocks:
            end = function_blocks[fb_start_address]['end']
            if end == 'END':
                end = (list(common_objs.disassembled_firmware.keys()))[-1]
            xref_to = self.get_xref_to(fb_start_address, end)
            function_blocks[fb_start_address]['xref_to'] = xref_to
        common_objs.function_blocks = function_blocks
        function_blocks = None
        
        # Get call depth.
        logging.info('Getting call-depth info.')
        function_blocks = self.get_call_depth_info()

    def get_xref_to(self, fb_start, fb_end):
        address = fb_start
        xref_to = []
        while ((address!=None) and (address <= fb_end)):
            address = self.get_next_address(self.all_addresses, address)
            if address == None: break
            if address > fb_end: break
            if address in common_objs.errored_instructions: break
            at_address = common_objs.disassembled_firmware[address]
            if at_address['is_data'] == True:
                continue
            insn = at_address['insn']
            if insn.id in [ARM_INS_B, ARM_INS_BL]:
                branch_target = insn.operands[0].value.imm
                end_func_block = utils.id_function_block_for_instruction(
                    branch_target
                )
                if end_func_block == fb_start:
                    continue
                if end_func_block not in xref_to:
                    xref_to.append(end_func_block)
        return xref_to
    
    def get_call_depth_info(self):
        for fb_start in common_objs.function_blocks:
            call_depth = self.get_fblock_call_depth(fb_start, [fb_start])
            common_objs.function_blocks[fb_start]['call_depth'] = call_depth
            logging.debug(
                'Call depth for function at '
                + hex(fb_start)
                + ' is '
                + str(call_depth)
            )
            
    def get_fblock_call_depth(self, fb_start_address, checked):
        all_counters = []
        fblock_obj = common_objs.function_blocks[fb_start_address]
        all_xref_tos = fblock_obj['xref_to']
        for item in checked:
            if item in all_xref_tos:
                all_xref_tos.remove(item)
        if all_xref_tos == []:
            return 0
        for xref_to in all_xref_tos:
            new_checked = copy.deepcopy(checked)
            new_checked.append(xref_to)
            new_counter = self.get_fblock_call_depth(
                xref_to,
                new_checked
            )
            all_counters.append(new_counter+1)
        counter = max(all_counters)
        return counter
                
    def add_basic_functions(self, function_block_start_addresses):
        # Add very first address.
        minimum_possible_address = common_objs.code_start_address
        function_block_start_addresses.append(minimum_possible_address)
        # Add interrupt addresses.
        for intrpt in common_objs.application_vector_table:
            if intrpt == 'initial_sp':
                continue
            function_block_start_addresses.append(
                common_objs.application_vector_table[intrpt]
            )
        # Add self-targeting branches.
        for ins_address in common_objs.disassembled_firmware:
            if ins_address < common_objs.code_start_address:
                continue
            if ins_address in common_objs.errored_instructions:
                continue
            at_address = common_objs.disassembled_firmware[ins_address]
            if at_address['is_data'] == True:
                continue
            if at_address['insn'].id == ARM_INS_B:
                branch_target = at_address['insn'].operands[0].value.imm
                if branch_target == ins_address:
                    if ins_address not in function_block_start_addresses:
                        function_block_start_addresses.append(ins_address)
        return function_block_start_addresses
 
    def check_branch_tos(self, function_block_start_addresses):
        certainties = ['high', 'med']
        for certainty in certainties:
            function_block_start_addresses = \
                self.check_branch_tos_at_certainty_level(
                    function_block_start_addresses,
                    certainty
                )
            
        return function_block_start_addresses
        
    def check_branch_tos_at_certainty_level(self, function_block_start_addresses,
                                            certainty_level):
        for ins_address in common_objs.disassembled_firmware:
            if ins_address in common_objs.errored_instructions:
                continue
            if ins_address < common_objs.code_start_address:
                continue
            # If it's data, rather than an instruction, then there is no use
            #  in continuing.
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
                
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            opcode_id = insn.id
            
            # Check whether the opcode is for a branch instruction at all.
            if opcode_id not in [ARM_INS_BL, ARM_INS_B]:
                continue
                
            # If the address has been flagged as a potential error, then 
            #  ignore it.
            if ins_address in common_objs.errored_instructions:
                continue

            # Conditional branches tend to be internal loops.
            if insn.cc != ARM_CC_AL:
                continue
                
            branch_address = insn.operands[0].value.imm
            if branch_address not in common_objs.disassembled_firmware:
                continue
            if branch_address < common_objs.code_start_address:
                common_objs.errored_instructions.append(ins_address)
                continue
            
            # If the branch to is POP, or branch, then more likely to be
            #  internal branch.
            insn = common_objs.disassembled_firmware[branch_address]['insn']
            if insn.id in [ARM_INS_POP, ARM_INS_B, ARM_INS_BL, 
                    ARM_INS_BLX, ARM_INS_BX]:
                continue
            
            if certainty_level == 'high':
                if opcode_id == ARM_INS_BL:
                    is_candidate = True
                else:
                    is_candidate = self.check_fb_candidate_high_certainty(
                            common_objs.disassembled_firmware,
                            branch_address
                        )
            elif certainty_level == 'med':
                is_candidate = self.check_fb_candidate_med_certainty(
                        common_objs.disassembled_firmware,
                        branch_address
                    )
                
            if is_candidate != True:
                continue
                
            # If we're at high certainty, then the function block list
            #  would have started out empty. Just add the addresses.
            if certainty_level == 'high':
                if branch_address not in function_block_start_addresses:
                    function_block_start_addresses.append(branch_address)
            else:
                preexists = self.check_preexisting_block(
                    function_block_start_addresses,
                    branch_address,
                    boundary=10
                )
                if preexists == False:
                    function_block_start_addresses.append(branch_address)
        return function_block_start_addresses

    def check_fb_candidate_high_certainty(self, disassembled_fw, branch_address):
        if branch_address in common_objs.errored_instructions:
            return False
        if disassembled_fw[branch_address]['is_data'] == True:
            return False
            
        insn = disassembled_fw[branch_address]['insn']
        if insn.id == ARM_INS_PUSH:
            return True
            
        if insn.mnemonic == ARM_INS_SUB:
            ops = insn.operands
            reg = ops[0].value.reg
            if reg == ARM_REG_SP:
                return True
        return False
        
    def check_fb_candidate_med_certainty(self, disassembled_fw, branch_address):
        # If the target is within 3 instructions of a push/sub-sp instruction, 
        #  take that to be true.
        list_to_iterate = [2, 4, 6]
        for i in list_to_iterate:
            if (branch_address + i) not in disassembled_fw:
                continue
            if (branch_address + i) in common_objs.errored_instructions:
                continue
            if disassembled_fw[branch_address + i]['is_data'] == True:
                continue
                
            if disassembled_fw[branch_address + i]['insn'].id == ARM_INS_PUSH:
                return True
                
            if disassembled_fw[branch_address + i]['insn'].id == ARM_INS_SUB:
                ops = disassembled_fw[branch_address + i]['insn'].operands
                reg = ops[0].value.reg
                if reg == ARM_REG_SP:
                    return True
        return False
        
    def check_for_nop_or_error(self, address, opcode, operands):
        if self.check_for_nop(opcode, operands) == True:
            return True
                    
        if address in common_objs.errored_instructions:
            return True

        return False
        
    def check_for_nop(self, opcode, operands):
        if opcode == ARM_INS_NOP:
            return True
        if opcode in [ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW]:
            if len(operands) == 2:
                if operands[0].value.reg == operands[1].value.reg:
                    return True
        return False
    
    def check_for_function_exit_ins(self, function_block_start_addresses):
        num_functions = len(function_block_start_addresses)
        new_function_block_start_addresses = []
        for idx, function_start in enumerate(function_block_start_addresses):
            fblock_start = function_start
            if idx == (num_functions-1):
                current_fblock_end = self.all_addresses[-1]
            else:
                all_address_index = self.all_addresses.index(
                    function_block_start_addresses[idx+1]
                )
                current_fblock_end = self.all_addresses[all_address_index-1]
            if (current_fblock_end-fblock_start) > 2500:
                new_function_block_start_addresses.append(fblock_start)
                return new_function_block_start_addresses
            new_function_blocks = self.analyse_function_block_for_exit_ins(
                fblock_start,
                current_fblock_end,
                [fblock_start]
            )
            for function_block in new_function_blocks:
                if function_block not in new_function_block_start_addresses:
                    new_function_block_start_addresses.append(function_block)
        return new_function_block_start_addresses
        
    def analyse_function_block_for_exit_ins(self, start, end, flist):
        address = start
        possible_endpoints = []
        branches = {}
        while address <= end:
            if address in common_objs.errored_instructions:
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            fw_bytes = common_objs.disassembled_firmware[address]
            
            # If we've got to a point that is data, then there must be
            # a way to skip over it (within a function.
            potential_end = False
            if fw_bytes['is_data'] == True:
                potential_end = True
            else:
                # Logical exit points for a function are bx and pop-pc.
                # Again, within a function, there must be a way to skip over them.
                insn = fw_bytes['insn']
                operands = insn.operands
                is_valid_exit = self.check_is_valid_exit(insn)
                if is_valid_exit == True:
                    potential_end = True
                    
            if potential_end == True:
                skip_end = False
                for branch_pt in branches:
                    target = branches[branch_pt]
                    if target > address:
                        skip_end = True
                        break
                if skip_end == True:
                    address = self.get_next_address(self.all_addresses, address)
                    if address == None: break
                    continue
                    
                next_ins = self.get_next_address(self.all_addresses, address)
                next_ins = self.get_valid_next_start(next_ins, end)
                if next_ins == None: break
                if next_ins > end:
                    break
                if (next_ins not in flist):
                    flist.append(next_ins)
                flist = self.analyse_function_block_for_exit_ins(
                    next_ins,
                    end, 
                    flist
                )
                break
                
            # Look at all the branch instructions.
            if insn.id in [ARM_INS_B, ARM_INS_CBNZ, ARM_INS_CBZ]:
                if insn.id == ARM_INS_B:
                    branch_target = operands[0].value.imm
                else:
                    branch_target = operands[1].value.imm
                if ((branch_target <= end) and (branch_target not in branches)):
                    branches[address] = branch_target
            
            # Analyse next instruction.
            address = self.get_next_address(self.all_addresses, address)
            if address == None: break
            continue

        return flist
        
    def get_valid_next_start(self, address, end):
        start = address    
        if address == None: return None
        while address <= end:
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                address = self.get_next_address(self.all_addresses, address)
                start = address
                if address == None:
                    break
                continue
            insn = common_objs.disassembled_firmware[address]['insn']
            if insn.id == ARM_INS_INVALID:
                break
            if self.check_for_nop(insn.id, insn.operands) == True:
                address = self.get_next_address(self.all_addresses, address)
                start = address
                if address == None:
                    break
                continue
            break
        return start
    
    def check_is_valid_exit(self, insn):
        if insn.id == ARM_INS_BX:
            return True
        if insn.id == ARM_INS_POP:
            operands = insn.operands
            final_operand = operands[-1]
            if final_operand.value.reg == ARM_REG_PC:
                return True
        return False
    
    def check_preexisting_block(self, function_block_start_addresses,
                                address, boundary=10):
        preexists = False
        function_block_start_addresses.sort()
        for existing_candidate_address in function_block_start_addresses:
            lower_bound = existing_candidate_address - boundary
            upper_bound = existing_candidate_address + boundary
            if (address > lower_bound) and (address < upper_bound):
                preexists = True
        return preexists
    
    #----------------- Find special functions ---------------------
    def identify_replace_functions(self):
        logging.info('Identifying pertinent functions.')
        (memset_address, reg_order, fixed_val) = \
            self.identify_memset()
        if memset_address != None:
            common_objs.replace_functions[memset_address] = {
                'type': consts.MEMSET,
                'pointer': reg_order[0],
                'value': reg_order[1],
                'length': reg_order[2],
                'fixed_value': fixed_val
            }
        udiv_address = self.identify_integer_udivision()
        if udiv_address != None:
            if udiv_address in common_objs.replace_functions:
                logging.error(
                    'Same address identified for another function as for '
                    'udiv: '
                    + hex(udiv_address)
                )
                return
            common_objs.replace_functions[udiv_address] = {
                'type': consts.UDIV
            }

    def identify_memset(self):
        memset_address = None
        possible_memsets = []
        for ins_address in common_objs.function_blocks:
            if ins_address in common_objs.errored_instructions:
                continue
            if 'xref_from' not in common_objs.disassembled_firmware[ins_address]:
                continue
            # memset would be BL.
            xrefs = common_objs.disassembled_firmware[ins_address]['xref_from']
            bl_xrefs = []
            for xref in xrefs:
                insn_id = common_objs.disassembled_firmware[xref]['insn'].id
                if insn_id == ARM_INS_BL:
                    bl_xrefs.append(xref)
            if len(bl_xrefs) < 2:
                continue
            start_address = ins_address
            
            (is_memset, reg_order, fixed_value) = self.check_for_memset(
                start_address
            )
            if is_memset == True:
                possible_memsets.append((ins_address, reg_order, fixed_value))

        if len(possible_memsets) > 1:
            possible_memsets = self.process_multiple_candidate_functions(
                possible_memsets
            )
        if len(possible_memsets) == 0:
            return (None, None, None)
        if len(possible_memsets) > 1: 
            logging.warning('Multiple candidates for memset. Using None.')
            return (None, None, None)
        memset_address = possible_memsets[0][0]
        logging.info(
            'Possible memset identified at ' 
            + hex(memset_address)
            + ' and memset_object: '
            + str(possible_memsets[0])
        )
        return possible_memsets[0]
            
    def process_multiple_candidate_functions(self, function_tuples):
        logging.debug('Processing multiple memset candidates.')
        functions = []
        for function_tuple in function_tuples:
            functions.append(function_tuple[0])
        caller_functions = []
        for idx, function in enumerate(functions):
            address = function
            ins_count = 0
            while ins_count < 10:
                if address in common_objs.errored_instructions:
                    address = self.get_next_address(self.all_addresses, address)
                    ins_count += 1
                    continue
                at_address = common_objs.disassembled_firmware[address]
                if ((at_address['is_data'] == True) 
                        or (at_address['insn'] == None)):
                    address = self.get_next_address(self.all_addresses, address)
                    ins_count += 1
                    continue
                if at_address['insn'].id == ARM_INS_B:
                    branch_target = (at_address['insn'].operands)[0].value.imm
                    if branch_target in functions:
                        caller_functions.append(function_tuples[idx])
                        break
                address = self.get_next_address(self.all_addresses, address)
                ins_count += 1
        for function in caller_functions:
            function_tuples.remove(function)
        return function_tuples
                    
    def check_for_memset(self, start_address):
        is_memset = False
        registers = None
        fixed_value = None
        address = start_address
        
        # Prelim check. STRB must be present.
        is_strb = False
        ins_count = 0
        ins_order = [address]
        while ins_count < 10:
            if address == None: break
            current_position = common_objs.disassembled_firmware[address]
            if ((current_position['is_data'] == True) 
                    or (current_position['insn'] == None)):
                address = self.get_next_address(self.all_addresses, address)
                ins_count += 1
                continue
                
            insn = current_position['insn']
            if insn.id == ARM_INS_STRB:
                is_strb = True
                break
            if (insn.id == ARM_INS_B):
                address = insn.operands[0].value.imm
                if address not in common_objs.disassembled_firmware:
                    address = self.get_next_address(self.all_addresses, address)
            else:
                address = self.get_next_address(self.all_addresses, address)
            ins_count += 1
            ins_order.append(address)
        # If there isn't a STRB instruction, we needn't look any further.
        if is_strb == False: return (is_memset, registers, fixed_value)

        # Now go through the instructions in order, keeping track
        #  of registers.
        if common_objs.compiler == consts.COMPILER_GCC:
            registers = [ARM_REG_R0,ARM_REG_R1,ARM_REG_R2]
        else:
            registers = [ARM_REG_R0,ARM_REG_R2,ARM_REG_R1]
        original_registers = copy.deepcopy(registers)
        for iaddress in ins_order:
            if iaddress in common_objs.errored_instructions:
                continue
            instruction = common_objs.disassembled_firmware[iaddress]['insn']
            if instruction == None:
                continue
            if common_objs.disassembled_firmware[iaddress]['is_data'] == True:
                continue
            operands = instruction.operands
            if instruction.id in [ARM_INS_MOV, ARM_INS_MOVW]:
                src_operand = operands[1].value.reg
                dst_operand = operands[0].value.reg
                if src_operand in registers:
                    src_index = registers.index(src_operand)
                    registers[src_index] = dst_operand
                elif (dst_operand == registers[1]):
                    fixed_value = operands[1].value.imm
            elif instruction.id == ARM_INS_STRB:
                str_value_reg = operands[0].value.reg
                str_mem_reg = operands[1].value.mem.base
                str_index = operands[1].value.mem.disp
                if ((str_mem_reg == registers[0])
                        and (str_value_reg == registers[1])
                        and (str_index == 0)):
                    is_memset = True
                break
        return (is_memset, original_registers, fixed_value)
        
    def identify_integer_udivision(self):
        if common_objs.arm_arch == consts.ARMv7M:
            return None
        possible_udivs = []
        for ins_address in common_objs.function_blocks:
            if ins_address in common_objs.errored_instructions:
                continue
            if 'xref_from' not in common_objs.disassembled_firmware[ins_address]:
                continue
            # udiv would be BL.
            xrefs = common_objs.disassembled_firmware[ins_address]['xref_from']
            bl_xrefs = []
            for xref in xrefs:
                insn_id = common_objs.disassembled_firmware[xref]['insn'].id
                if insn_id == ARM_INS_BL:
                    bl_xrefs.append(xref)
            if len(bl_xrefs) < 1:
                continue
            start_address = ins_address
            
            is_udiv = self.check_udiv(start_address)
            if is_udiv == True:
                possible_udivs.append(start_address)
        
        if len(possible_udivs) == 0:
            return None
        if len(possible_udivs) > 1:
            logging.info(
                'Multiple possibilities for udiv. Using None.'
            )
            return None
        udiv_address = possible_udivs[0]
        logging.info(
            'Possible udiv identified at '
            + hex(udiv_address)
        )
        return udiv_address
            
    def check_udiv(self, start_address):
        end_of_block = utils.id_function_block_end(start_address)
        numerator = ARM_REG_R0
        denominator = ARM_REG_R1
        num_lsr = 0
        address = start_address
        while address <= end_of_block:
            if ((address in common_objs.errored_instructions) 
                    or (common_objs.disassembled_firmware[address]['is_data'] == True)):
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue

            insn = common_objs.disassembled_firmware[address]['insn']

            # Instructions we don't expect to find.
            if insn.id in [ARM_INS_LDM, ARM_INS_LDR, ARM_INS_LDREX, 
                    ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH, 
                    ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB, ARM_INS_LDRD,
                    ARM_INS_STR, ARM_INS_STREX, ARM_INS_STRH, ARM_INS_STREXH, 
                    ARM_INS_STRB, ARM_INS_STREXB, ARM_INS_STRD, ARM_INS_STM,
                    ARM_INS_SVC, ARM_INS_AND]:
                return False
                
            operands = insn.operands
            if insn.id in [ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW]:
                if operands[1].value.reg == numerator:
                    numerator = operands[0].value.reg
                elif operands[1].value.reg == denominator:
                    denominator = operands[0].value.reg
            if insn.id == ARM_INS_LSR:
                if len(operands) == 2:
                    src_operand = operands[0]
                else:
                    src_operand = operands[1]
                if src_operand.value.reg == numerator:
                    num_lsr += 1
            address = self.get_next_address(self.all_addresses, address)
            if address == None: break
        if num_lsr == 0:
            return False
        logging.debug(
            'Function matches signature for udiv: '
            + hex(start_address)
        )
        return True
    
    #------------------ Blacklisted functions ----------------
    def populate_blacklist(self):
        logging.info('Populating function blacklist.')
        
        blacklisted_functions = []
        for intrpt in common_objs.application_vector_table:
            if intrpt == 'initial_sp':
                continue
            if intrpt == 'reset':
                continue
            blacklisted_functions.append(
                common_objs.application_vector_table[intrpt]
            )
            
        for function_block in common_objs.function_blocks:
            if function_block in blacklisted_functions:
                continue
            blacklist_function = self.check_function_to_blacklist(
                function_block,
                common_objs.function_blocks[function_block]
            )
            if blacklist_function == True:
                logging.debug(
                    'Blacklisting function block beginning at '
                    + hex(function_block)
                )
                blacklisted_functions.append(function_block)
        common_objs.blacklisted_functions = blacklisted_functions
        
    def check_function_to_blacklist(self, fb_start_address, func_block):
        """Check whether a function block should be excluded from traces."""
        fb_end_address = func_block['end']
        if fb_end_address == 'END': fb_end_address = self.all_addresses[-1]
        logging.trace(
            'Testing function block beginning at '
            + hex(fb_start_address)
            + ' and ending at '
            + hex(fb_end_address)
        )
            
        address = fb_start_address
        while ((address != None) and (address <= fb_end_address)):
            if address not in common_objs.disassembled_firmware:
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            if address in common_objs.errored_instructions:
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            at_address = common_objs.disassembled_firmware[address]
            insn = at_address['insn']
            if insn.id in [ARM_INS_DSB, ARM_INS_DMB]:
                return True
            if ((insn.id in [ARM_INS_B, ARM_INS_BL]) and (insn.cc == ARM_CC_AL)):
                branch_target = insn.operands[0].value.imm
                if branch_target == address:
                    return True
                if branch_target < address:
                    if 'last_insn_address' not in at_address:
                        return True
                    last_ins_for_target = at_address['last_insn_address']
                    if last_ins_for_target == branch_target:
                        return True
            address = self.get_next_address(self.all_addresses, address)
            if address == None: break
        return False
        
    def check_all_nop_error(self, start_address, end_address):
        all_nop_error = True
        address = start_address
        while ((address != None) and (address < end_address)):
            if address not in common_objs.disassembled_firmware:
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            if address in common_objs.errored_instructions:
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                address = self.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            insn = common_objs.disassembled_firmware[address]['insn']
            opcode = insn.id
            operands = insn.operands
            is_nop_error = self.check_for_nop_or_error(
                address,
                opcode,
                operands
            )
            if is_nop_error == False:
                all_nop_error = False
            address = self.get_next_address(self.all_addresses, address)
            if address == None: break
        return all_nop_error
    
    def get_next_address(self, address_obj, ins_address):
        if address_obj == None: return None
        if ins_address == None: return None
        
        if ins_address not in address_obj:
            for x in range(len(address_obj)):
                address = address_obj[x]
                if ins_address > address:
                    ins_address = address
                    break
        if ins_address not in address_obj: return None
        
        # Find index of the address and get next one up.
        if (address_obj.index(ins_address)) < (len(address_obj) - 1):
            next_address = address_obj[address_obj.index(ins_address) + 1]
        else:
            next_address = None
        return next_address
        
    def get_previous_address(self, address_obj, address):
        if address_obj == None: return None
        if address == None: return None
        
        if address in address_obj:
            index = address_obj.index(address)
            if index == 0:
                return None
            prev_address = address_obj[index - 1]
        else:
            prev_address = self.get_previous_partial_address(
                address_obj,
                address
            )
        return prev_address
    
    def get_previous_partial_address(self, address_obj, address):
        if address_obj == None: return None
        if address == None: return None
            
        if address not in address_obj:
            for i in range(1,4):
                if (address-i) in address_obj:
                    address = address-i
                    break
        return address