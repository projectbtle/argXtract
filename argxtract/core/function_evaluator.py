import os
import sys
import copy
import logging
from capstone import *
from capstone.arm import *
from argxtract.common import paths as common_paths
from argxtract.core import utils
from argxtract.core import consts
from argxtract.core import binary_operations as binops
from argxtract.common import objects as common_objs


class FunctionEvaluator:
    def __init__(self):
        pass
        
    def estimate_function_blocks(self):
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
        function_block_start_addresses = self.estimate_functions_using_exit_points(
            function_block_start_addresses
        )
        function_block_start_addresses.sort()
        
        # Remove the switch function addresses from common_objs.replace_functions.
        switch_addresses = []
        for address in common_objs.replace_functions:
            if (common_objs.replace_functions[address]['type'] 
                    in [consts.FN_ARMSWITCH8, consts.FN_GNUTHUMB, consts.FN_GNUTHUMBCALL]):
                switch_addresses.append(address)
        for switch_address in switch_addresses:
            common_objs.replace_functions.pop(switch_address, None)
        
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
                end = all_addresses[-1]
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
        while ((address != None) and (address <= fb_end)):
            address = utils.get_next_address(self.all_addresses, address)
            if address == None: break
            if address > fb_end: break
            if address in common_objs.errored_instructions: break
            if utils.is_valid_code_address(address) != True:
                continue
            insn = common_objs.disassembled_firmware[address]['insn']
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
        #for ins_address in common_objs.self_targeting_branches:
        #    function_block_start_addresses.append(ins_address)
        return function_block_start_addresses
 
    def check_branch_tos(self, function_block_start_addresses):
        logging.debug(
            'Checking for high-certainty functions.'
        )
        functions = []
        for ins_address in common_objs.disassembled_firmware:
            if ins_address < common_objs.code_start_address:
                continue
            if ins_address > common_objs.code_end_address:
                break
            # If it's data, rather than an instruction, then there is no use
            #  in continuing.
            if utils.is_valid_code_address(ins_address) != True:
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
                logging.trace(
                    'Branch target ('
                    + hex(branch_address)
                    + ') is less than the code start address ('
                    + hex(common_objs.code_start_address)
                    + ') for branch call at '
                    + hex(ins_address)
                    + '. Adding to errored instructions.'
                )
                continue
            
            # If the branch to is POP, or branch, then more likely to be
            #  internal branch.
            insn = common_objs.disassembled_firmware[branch_address]['insn']
            if insn == None: continue
            if insn.id in [ARM_INS_POP, ARM_INS_B, ARM_INS_BL, 
                    ARM_INS_BLX, ARM_INS_BX]:
                continue
            
            if opcode_id == ARM_INS_BL:
                is_candidate = True
            else:
                is_candidate = self.check_fb_candidate_high_certainty(
                        common_objs.disassembled_firmware,
                        branch_address
                    )

            if is_candidate != True:
                continue
            
            if branch_address not in function_block_start_addresses:
                function_block_start_addresses.append(branch_address)
                functions.append(hex(branch_address))
                
        functions.sort()
        logging.debug(
            'Functions identified: '
            + str(functions)
        )                
        return function_block_start_addresses

    def check_fb_candidate_high_certainty(self, disassembled_fw, branch_address):
        if utils.is_valid_code_address(branch_address) != True:
            return False
            
        insn = disassembled_fw[branch_address]['insn']

        if insn.id == ARM_INS_PUSH:
            return True
            
        if insn.id == ARM_INS_SUB:
            ops = insn.operands
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
    
    def estimate_functions_using_exit_points(self, function_block_start_addresses):
        logging.debug('Estimating functions using exit instructions.')
        num_functions = len(function_block_start_addresses)
        new_function_block_start_addresses = []
        overrun = None
        idx = 0
        while idx < num_functions:
            fblock_start = function_block_start_addresses[idx]
            if idx == (num_functions-1):
                current_fblock_end = self.all_addresses[-1]
            else:
                all_address_index = self.all_addresses.index(
                    function_block_start_addresses[idx+1]
                )
                current_fblock_end = self.all_addresses[all_address_index-1]
            (new_function_blocks, overrun) = self.analyse_function_block_for_exit_ins(
                fblock_start,
                current_fblock_end,
                [fblock_start]
            )
            
            while overrun != None:
                current_index = function_block_start_addresses.index(fblock_start)

                i = current_index+1
                for i in range(current_index+1, len(function_block_start_addresses)):
                    all_address_index = self.all_addresses.index(
                        function_block_start_addresses[i]
                    )
                    new_fblock_end = self.all_addresses[all_address_index-1]
                    if overrun < function_block_start_addresses[i]:
                        break
                        
                idx = i-1
                
                (new_function_blocks, overrun) = self.analyse_function_block_for_exit_ins(
                    fblock_start,
                    new_fblock_end,
                    [fblock_start]
                )
            for function_block in new_function_blocks:
                if function_block not in new_function_block_start_addresses:
                    new_function_block_start_addresses.append(function_block)
            idx += 1
                    
        return new_function_block_start_addresses
        
    def analyse_function_block_for_exit_ins(self, start, end, flist):
        logging.debug(
            'Function block estimation for super-block beginning at '
            + hex(start)
            + ' and end '
            + hex(end)
        )
        address = start
        min_address = ''
        possible_endpoints = []
        branches = {}
        while address <= end:
            if address in common_objs.errored_instructions:
                address = utils.get_next_address(self.all_addresses, address)
                if address == None: break
                continue
            fw_bytes = common_objs.disassembled_firmware[address]
                
            # If we've got to a point that is data, then there must be
            # a way to skip over it (within a function).
            potential_end = False
            is_valid_code_address = utils.is_valid_code_address(address)
            if is_valid_code_address != True:
                potential_end = True
            else:
                # Logical exit points for a function are bx, pop-pc and 
                #  unconditional self-targeting branches.
                # Again, within a function, there must be a way to skip over them.
                insn = fw_bytes['insn']
                operands = insn.operands
                is_valid_exit = self.check_is_valid_exit(address, start, end)
                if is_valid_exit == True:
                    potential_end = True
                    
            # This is needed here because of unconditional branches.
            if (is_valid_code_address == True):
                if ((insn.id == ARM_INS_B) and (insn.cc == ARM_CC_AL)):
                    branch_target = operands[0].value.imm
                    if address not in branches:
                        branches[address] = [branch_target]
                    
            if potential_end == True:
                skip_end = False
                for branch_pt in branches:
                    targets = branches[branch_pt]
                    for target in targets:
                        if target > address:
                            skip_end = True
                            break
                if skip_end == True:
                    address = utils.get_next_address(self.all_addresses, address)
                    if address == None: break
                    continue
                    
                next_ins = utils.get_next_address(self.all_addresses, address)
                next_ins = self.get_valid_next_start(next_ins, end)
                if next_ins == None: break
                if next_ins > end:
                    break
                if (next_ins not in flist):
                    flist.append(next_ins)
                (flist, _) = self.analyse_function_block_for_exit_ins(
                    next_ins,
                    end, 
                    flist
                )
                break
                
            # Look at PC switch.
            is_candidate_address = False
            if address in common_objs.replace_functions:
                if (common_objs.replace_functions[address]['type'] 
                        in [consts.PC_SWITCH, consts.FN_GNUTHUMBCALL, 
                            consts.FN_ARMSWITCH8CALL]):
                    is_candidate_address = True
                    original_address = address
                    table_branch_addresses = \
                        common_objs.replace_functions[original_address]['table_branch_addresses']
                # With PC switch, the next addresses may not immediately follow
                #  the PC operation.
                    if (common_objs.replace_functions[address]['type'] 
                            in [consts.FN_GNUTHUMBCALL, consts.FN_ARMSWITCH8CALL]):
                        address = common_objs.replace_functions[original_address]['table_branch_max']
                    else:
                        address = utils.get_next_address(self.all_addresses, address)
            elif is_valid_code_address == True:
                if insn.id in [ARM_INS_TBB, ARM_INS_TBH]:
                    original_address = address
                    if original_address in common_objs.table_branches:
                        table_branch_addresses = \
                            common_objs.table_branches[original_address]['table_branch_addresses']
                        address = common_objs.table_branches[original_address]['table_branch_max']
                        is_candidate_address = True
                # Look at all the branch instructions.
                elif insn.id in [ARM_INS_B, ARM_INS_CBNZ, ARM_INS_CBZ]:
                    if (insn.id == ARM_INS_B):
                        branch_target = operands[0].value.imm
                    else:
                        branch_target = operands[1].value.imm
                    if (branch_target <= end):
                        if address not in branches:
                            branches[address] = [branch_target]

            # If we've marked an ARM_SWITCH8, GNU_THUMB or TBB/TBH, 
            #  then process the table.
            if is_candidate_address == True:
                branches[original_address] = table_branch_addresses
                largest_table_address = max(table_branch_addresses)
                min_address = largest_table_address
                if min_address > end:
                    logging.error(
                        'Table address ('
                        + hex(min_address)
                        + ') is greater than function end! '
                        + hex(original_address)
                    )
                    return (flist, min_address)
                if address%2 == 1: address-=1
                logging.debug(
                    'Processed table branch at '
                    + hex(original_address)
                    + '. Now skipping to ' 
                    + hex(address)
                )
            
            # Analyse next instruction.
            if is_candidate_address == False:
                address = utils.get_next_address(self.all_addresses, address)
                if address == None: break
            continue

        return (flist, None)
        
    def get_valid_next_start(self, address, end):
        start = address    
        if address == None: return None
        while address <= end:
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                address = utils.get_next_address(self.all_addresses, address)
                start = address
                if address == None:
                    break
                continue
            insn = common_objs.disassembled_firmware[address]['insn']
            if insn == None: 
                address = utils.get_next_address(self.all_addresses, address)
                start = address
                if address == None:
                    break
                continue
            if insn.id == ARM_INS_INVALID:
                break
            if self.check_for_nop(insn.id, insn.operands) == True:
                address = utils.get_next_address(self.all_addresses, address)
                start = address
                if address == None:
                    break
                continue
            break
        return start
    
    def check_is_valid_exit(self, ins_address, start, end):
        insn = common_objs.disassembled_firmware[ins_address]['insn']
        if insn == None: return True
        if insn.id == ARM_INS_BX:
            return True
        if insn.id == ARM_INS_POP:
            operands = insn.operands
            final_operand = operands[-1]
            if final_operand.value.reg == ARM_REG_PC:
                return True
        if insn.id == ARM_INS_B:
            if insn.cc == ARM_CC_AL:
                return True
                target_address_int = insn.operands[0].value.imm
                target_address = hex(target_address_int)
                if target_address_int == ins_address:
                    return True
                # Wouldn't any unconditional branch to lower address be an exit?
                if target_address_int < ins_address:
                    return True
        return False
    
    #----------------- Find special functions ---------------------
    def perform_function_pattern_matching(self):
        # When function patterns are used for COIs, 
        #  this is where we would process those too.
        logging.info('Identifying pertinent functions.')
        (memset_address, reg_order, fixed_val) = \
            self.identify_memset()
        if memset_address != None:
            common_objs.replace_functions[memset_address] = {
                'type': consts.FN_MEMSET,
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
                'type': consts.FN_UDIV
            }

    def identify_memset(self):
        memset_address = None
        possible_memsets = []
        for ins_address in common_objs.function_blocks:
            if ins_address in common_objs.errored_instructions:
                continue
            if ins_address in common_objs.denylisted_functions:
                continue
            # memset would have call depth of 0.
            if common_objs.function_blocks[ins_address]['call_depth'] > 0:
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
            if len(bl_xrefs) < 1: continue # There are instances where there is only a single call to memset.
            start_address = ins_address
            end_address = utils.id_function_block_end(start_address)
            (is_memset, reg_order, fixed_value) = self.check_for_memset(
                start_address,
                end_address,
                [ARM_REG_R0,ARM_REG_R1,ARM_REG_R2]
            )
            if is_memset == True:
                possible_memsets.append((ins_address, reg_order, fixed_value))
            (is_memset, reg_order, fixed_value) = self.check_for_memset(
                start_address,
                end_address,
                [ARM_REG_R0,ARM_REG_R2,ARM_REG_R1]
            )
            if is_memset == True:
                possible_memsets.append((ins_address, reg_order, fixed_value))

        if len(possible_memsets) > 1:
            possible_memsets = self.process_multiple_candidate_functions(
                possible_memsets
            )
        if len(possible_memsets) == 0:
            logging.warning('No candidates for memset.')
            return (None, None, None)
        if len(possible_memsets) > 1: 
            for possible_memset in possible_memsets:
                logging.debug(
                    'Function matches signature for memset: '
                    + hex(possible_memset[0])
                )
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
                    address = utils.get_next_address(self.all_addresses, address)
                    ins_count += 1
                    continue
                at_address = common_objs.disassembled_firmware[address]
                if ((at_address['is_data'] == True) 
                        or (at_address['insn'] == None)):
                    address = utils.get_next_address(self.all_addresses, address)
                    ins_count += 1
                    continue
                if at_address['insn'].id == ARM_INS_B:
                    branch_target = (at_address['insn'].operands)[0].value.imm
                    if branch_target in functions:
                        caller_functions.append(function_tuples[idx])
                        break
                address = utils.get_next_address(self.all_addresses, address)
                ins_count += 1
        for function in caller_functions:
            function_tuples.remove(function)
        return function_tuples
                    
    def check_for_memset(self, start_address, end_address, registers):
        is_memset = False
        fixed_value = None
        
        # Preliminary checks (if any of the input registers are overwritten
        #  in the first instruction, then it can't be the function we want.
        first_ins = common_objs.disassembled_firmware[start_address]['insn']
        if (first_ins.id in [ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW]):
            if first_ins.operands[0].value.reg in registers:
                return (False, None, None)
                
        address = start_address
        end_address = utils.id_function_block_end(start_address)
        # Prelim checks. STRB, CMP (or conditional branch) must be present.
        # LDR must not.
        is_ldr = False
        is_strb = False
        is_cmp = False
        is_self_branch = False
        while address <= end_address:
            if address in common_objs.self_targeting_branches:
                is_self_branch = True
                break
                
            current_position = common_objs.disassembled_firmware[address]
            if ((current_position['is_data'] == True) 
                    or (current_position['insn'] == None)):
                address = utils.get_next_address(self.all_addresses, address)
                continue
                
            insn = current_position['insn']
            if insn.id == ARM_INS_STRB:
                is_strb = True
            if insn.id in [ARM_INS_LDM, ARM_INS_LDR, ARM_INS_LDREX, 
                    ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH, 
                    ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB, ARM_INS_LDRD]:
                is_ldr = True
            if insn.id == ARM_INS_CMP:
                is_cmp = True
            if ((insn.id == ARM_INS_B) 
                    and (insn.cc != ARM_CC_AL) 
                    and (insn.cc != ARM_CC_INVALID)):
                is_cmp = True
            address = utils.get_next_address(self.all_addresses, address)
            
        # Memset doesn't have self-targeting branches.
        if is_self_branch == True: return (False, None, None)
        # If there isn't a STRB or CMP instruction, we needn't look any further.
        if ((is_strb == False) or (is_cmp == False) or (is_ldr == True)): 
            return (False, None, None)
        
        # Create an ordered set of instructions.
        address = start_address
        ins_count = 0
        ins_order = [address]
        while ins_count < 10:
            if address == None: break
            current_position = common_objs.disassembled_firmware[address]
            if ((current_position['is_data'] == True) 
                    or (current_position['insn'] == None)):
                address = utils.get_next_address(self.all_addresses, address)
                ins_count += 1
                continue
                
            insn = current_position['insn']
            if (insn.id == ARM_INS_B):
                address = insn.operands[0].value.imm
                if address not in common_objs.disassembled_firmware:
                    address = utils.get_next_address(self.all_addresses, address)
            else:
                address = utils.get_next_address(self.all_addresses, address)
                
            ins_count += 1
            ins_order.append(address)
        
        # Now go through the instructions in order, keeping track
        #  of registers.
        original_registers = copy.deepcopy(registers)
        for iaddress in ins_order:
            if utils.is_valid_code_address(iaddress) != True:
                continue
            instruction = common_objs.disassembled_firmware[iaddress]['insn']
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
            if ins_address in common_objs.denylisted_functions:
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
                    or (common_objs.disassembled_firmware[address]['is_data'] == True)
                    or (common_objs.disassembled_firmware[address]['insn'] == None)):
                address = utils.get_next_address(self.all_addresses, address)
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
            address = utils.get_next_address(self.all_addresses, address)
            if address == None: break
        if num_lsr == 0:
            return False
        logging.debug(
            'Function matches signature for udiv: '
            + hex(start_address)
        )
        return True
    
    #------------------ denylisted functions ----------------
    def populate_denylist(self):
        logging.info('Populating function denylist.')
        
        denylisted_functions = []
        for intrpt in common_objs.application_vector_table:
            if intrpt == 'initial_sp':
                continue
            if intrpt == 'reset':
                continue
            denylisted_functions.append(
                common_objs.application_vector_table[intrpt]
            )
            
        for function_block in common_objs.function_blocks:
            if function_block in denylisted_functions:
                continue
            denylist_function = self.check_function_to_denylist(
                function_block,
                common_objs.function_blocks[function_block]
            )
            if denylist_function == True:
                logging.debug(
                    'denylisting function block beginning at '
                    + hex(function_block)
                )
                denylisted_functions.append(function_block)
        common_objs.denylisted_functions = denylisted_functions
        
    def check_function_to_denylist(self, fb_start_address, func_block):
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
            if utils.is_valid_code_address(address) != True:
                address = utils.get_next_address(self.all_addresses, address)
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
            address = utils.get_next_address(self.all_addresses, address)
            if address == None: break
        return False