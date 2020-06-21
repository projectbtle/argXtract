import os
import sys
import copy
import logging
from capstone import *
from capstone.arm import *
from svcxtract.common import paths as common_paths
from svcxtract.core import utils
from svcxtract.core import consts
from svcxtract.common import objects as common_objs


class FunctionEvaluator:
    def __init__(self):
        pass
        
    def perform_function_block_analysis(self):
        logging.info(
            'Performing function block analyses.'
        )
        self.all_addresses = list(common_objs.disassembled_firmware.keys())
        
        # Identify function blocks.
        self.find_function_blocks()
        
        # Identify important functions (like memset)
        self.identify_memory_access_functions()
        
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
        # TODO: This results in quite a few incorrect boundaries,
        #  because in some cases the function starts with LDR.
        function_block_start_addresses = self.check_opcodes_for_fb_start(
            function_block_start_addresses
        )
        function_block_start_addresses.sort()
        
        # Step 3.
        # Prune the function blocks.
        function_block_start_addresses = self.prune_function_blocks(
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
        logging.debug(debug_msg)
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
        certainties = ['high', 'med', 'low']
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
            elif certainty_level == 'low':
                is_candidate = self.check_fb_candidate_low_certainty(
                        common_objs.disassembled_firmware,
                        branch_address,
                        ins_address
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
        
    def check_fb_candidate_low_certainty(self, disassembled_fw, branch_address,
                                            ins_address):
        # If the preceding instruction is "pop {pc}" or "bx", then it may be
        #  the end of a function.
        
        # If one of the preceding 3 instructions are nops, bx lr, pop {pc},
        #  data or errors, then it may signify the end of a function (in GCC)?
        # However, if all instructions between the branch instruction
        #  and its target are nops or data, then do not assume it to be 
        #  a function block start.
        if ins_address < branch_address:
            if 'last_insn_address' not in disassembled_fw[branch_address]:
                return False
            last_ins_for_target = \
                disassembled_fw[branch_address]['last_insn_address']
            if last_ins_for_target == ins_address:
                return False
                
        nop_error_data_count = 0
        list_to_iterate = [2, 4, 6]
        append_counter = 0
        for j in list_to_iterate:
            # If the address we're looking for doesn't exist,
            #  add a new value to list.
            if (branch_address - j) not in disassembled_fw:
                if append_counter < 3:
                    list_to_iterate.append(list_to_iterate[-1] + 2)
                    append_counter += 1
                continue
            
            # If preceding instruction is data, then it MAY signify end of FB.
            if disassembled_fw[branch_address - j]['is_data'] == True:
                nop_error_data_count += 1
                continue
              
            # If preceding instruction is "bx lr", then it may signify end of FB.
            if disassembled_fw[branch_address - j]['insn'].id == ARM_INS_BX:
                operands = disassembled_fw[branch_address - j]['insn'].operands
                final_operand = operands[-1]
                if final_operand.value.reg == ARM_REG_LR:
                    nop_error_data_count += 1
                    continue
                    
            # If preceding instruction is "pop {pc}", then it may signify 
            #  end of FB.
            if disassembled_fw[branch_address - j]['insn'].id == ARM_INS_POP:
                operands = disassembled_fw[branch_address - j]['insn'].operands
                final_operand = operands[-1]
                if final_operand.value.reg == ARM_REG_PC:
                    nop_error_data_count += 1
                    continue
                        
            # If preceding instruction is skipdata, then it MAY signify end of FB. 
            if (disassembled_fw[branch_address - j]['insn'].id) == 0:
                nop_error_data_count += 1
                continue
               
            # If preceding instruction is nop/error, then it MAY signify end of FB.                
            is_nop_or_error = self.check_for_nop_or_error(
                branch_address - j,
                disassembled_fw[branch_address - j]['insn'].id,
                disassembled_fw[branch_address - j]['insn'].operands
            )
            if is_nop_or_error == True:
                nop_error_data_count += 1
        if nop_error_data_count > 2:
            return True
        return False
        
    def check_for_nop_or_error(self, address, opcode, operands):
        # If we have mov with the same src and dst regsiters, then it's a nop.
        if opcode == ARM_INS_NOP:
            return True
            
        if opcode in [ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW]:
            if len(operands) == 2:
                if operands[0].value.reg == operands[1].value.reg:
                    return True
                    
        if address in common_objs.errored_instructions:
            return True

        return False
    
    def check_opcodes_for_fb_start(self, function_block_start_addresses):
        for ins_address in common_objs.disassembled_firmware:
            if ins_address in common_objs.errored_instructions:
                continue
            if ins_address < common_objs.code_start_address:
                continue
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            opcode_id = insn.id
            is_candidate = False
            if (opcode_id == ARM_INS_PUSH):
                is_candidate = True
            if (opcode_id == ARM_INS_SUB):
                ops = insn.operands
                reg = ops[0].value.reg
                if reg == ARM_REG_SP:
                    is_candidate = True
            if is_candidate != True:
                continue
            if ins_address in function_block_start_addresses:
                continue
            
            preexists = self.check_preexisting_block(
                function_block_start_addresses,
                ins_address,
                boundary=26
            )
            if preexists == False:
                function_block_start_addresses.append(ins_address)
        return function_block_start_addresses
        
    def check_preexisting_block(self, function_block_start_addresses,
                                address, boundary=10):
        preexists = False
        for existing_candidate_address in function_block_start_addresses:
            lower_bound = existing_candidate_address - boundary
            upper_bound = existing_candidate_address + boundary
            if (address > lower_bound) and (address < upper_bound):
                preexists = True
        return preexists
        
    def prune_function_blocks(self, function_block_start_addresses):
        logging.debug('Pruning function list.')
        function_block_start_addresses = list(set(function_block_start_addresses))
        fblocks_to_delete = []
        
        # We add the existing function blocks to common_objs, but 
        #  only temporarily.
        temp_obj = {}
        for fblock in function_block_start_addresses:
            temp_obj[fblock] = {}
        common_objs.function_blocks = temp_obj
        
        # Now we go through the instructions and make sure all conditional 
        #  branches occur within the same function block.
        # The only problem is that stripped binaries don't can contain 
        #  incorrect conditional branches (i.e., data that is interpreted as 
        #  instruction.
        for ins_address in common_objs.disassembled_firmware:
            if ins_address in common_objs.errored_instructions:
                continue
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn.id not in [ARM_INS_B, ARM_INS_CBNZ, ARM_INS_CBZ]:
                continue
            if insn.id == ARM_INS_B:
                if ((insn.cc == ARM_CC_AL) or (insn.cc == ARM_CC_INVALID)):
                    continue
                branch_target = insn.operands[0].value.imm
            elif insn.id in [ARM_INS_CBNZ, ARM_INS_CBZ]:
                branch_target = insn.operands[1].value.imm
            
            # If the target has the signature of a high- or medium-certainty 
            #  function block, then don't remove it.
            is_high_certainty_fblock = self.check_fb_candidate_high_certainty(
                common_objs.disassembled_firmware, 
                branch_target
            )
            if is_high_certainty_fblock == True:
                continue
            is_med_certainty_fblock = self.check_fb_candidate_med_certainty(
                common_objs.disassembled_firmware, 
                branch_target
            )
            if is_med_certainty_fblock == True:
                continue
            
            src_block = utils.id_function_block_for_instruction(ins_address)
            dst_block = utils.id_function_block_for_instruction(branch_target)
            if src_block == dst_block:
                continue
            if branch_target > ins_address:
                fblock_to_delete = dst_block
            else:
                fblock_to_delete = src_block
            
            # Now we can mark the function block for deletion.
            if fblock_to_delete not in fblocks_to_delete:
                fblocks_to_delete.append(fblock_to_delete)
            logging.debug(
                'Marking function block starting at '
                + hex(fblock_to_delete)
                + ' pointed to by instruction '
                + hex(ins_address)
                + ' for deletion.'
            )
                
        # Remove the identified function blocks.
        for fblock_to_delete in fblocks_to_delete:
            if fblock_to_delete in function_block_start_addresses:
                function_block_start_addresses.remove(fblock_to_delete)
                
        return function_block_start_addresses
    
    #----------------- Find special functions ---------------------
    def identify_memory_access_functions(self):
        logging.info('Identifying pertinent functions.')
        (memset_address, reg_order, fixed_val) = \
            self.identify_memset()
        if memset_address != None:
            common_objs.memory_access_functions[memset_address] = {
                'type': consts.MEMSET,
                'pointer': reg_order[0],
                'value': reg_order[1],
                'length': reg_order[2],
                'fixed_value': fixed_val
            }

    def identify_memset(self):
        memset_address = None
        possible_memsets = []
        for ins_address in common_objs.disassembled_firmware:
            if ins_address in common_objs.errored_instructions:
                continue
            if ins_address < common_objs.code_start_address:
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
        if len(possible_memsets) > 1: 
            logging.warning('Multiple candidates for memset. Using None.')
            return (None, None, None)
        elif len(possible_memsets) == 0:
            return (None, None, None)
        else:
            memset_address = possible_memsets[0][0]
            logging.info(
                'Possible memset identified at ' 
                + hex(memset_address)
                + ' and memset_object: '
                + str(possible_memsets[0])
            )
            return possible_memsets[0]
            
    def process_multiple_candidate_functions(self, function_tuples):
        functions = []
        for function_tuple in function_tuples:
            functions.append(function_tuple[0])
        blacklisted_functions = []
        for idx, function in enumerate(functions):
            address = function
            ins_count = 0
            while ins_count < 10:
                at_address = common_objs.disassembled_firmware[address]
                if ((at_address['is_data'] == True) 
                        or (at_address['insn'] == None)):
                    address = self.get_next_address(self.all_addresses, address)
                    ins_count += 1
                    continue
                if at_address['insn'].id == ARM_INS_B:
                    branch_target = (at_address['insn'].operands)[0].value.imm
                    if branch_target in functions:
                        blacklisted_functions.append(function_tuples[idx])
                        break
                address = self.get_next_address(self.all_addresses, address)
                ins_count += 1
        for function in blacklisted_functions:
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
                continue
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                address = self.get_next_address(self.all_addresses, address)
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
        return False
        
    def check_all_nop_error(self, start_address, end_address):
        all_nop_error = True
        address = start_address
        while ((address != None) and (address < end_address)):
            if address not in common_objs.disassembled_firmware:
                address = self.get_next_address(self.all_addresses, address)
                continue
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                address = self.get_next_address(self.all_addresses, address)
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