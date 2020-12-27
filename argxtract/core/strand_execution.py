import os
import sys
import copy
import json
import struct
import timeit
import pickle
import logging
import hashlib
import collections
import numpy as np
from capstone import *
from capstone.arm import *
from random import getrandbits
from argxtract.core import utils
from argxtract.core import consts
from argxtract.core import binary_operations as binops
from argxtract.common import paths as common_paths
from argxtract.common import objects as common_objs


class StrandExecution:
    """This is essentially a simplified version of the RegisterEvaluator."""
    
    def __init__(self, all_addresses):
        self.max_time = 300
        self.end_points = []
        self.all_addresses = all_addresses
        self.check_error = True
        
    def trace_register_values(self, insn_object, start_point, end_points, 
            register_object, memory_map, condition_flags, exec_last=False, 
            check_error=True):
        logging.debug(  
            'Starting strand trace at '
            + hex(start_point)
            + ' with end points '
            + str(end_points)
            + ' and '
            + str(register_object)
        )
        start_time = timeit.default_timer()
        self.check_error = check_error
        
        ins_address = start_point
        code_end = common_objs.code_end_address
        while ins_address <= code_end:
            if ((timeit.default_timer() - start_time) > self.max_time):
                return (ins_address, memory_map, register_object)
                
            register_object[ARM_REG_PC] = self.get_pc_value(ins_address)
        
            pre_exec_address = ins_address
            
            # If we have arrived at an end point, then
            #  return the registers and memory map.
            if exec_last == False:
                if ins_address in end_points:
                    return (ins_address, memory_map, register_object)

            # Instructions we needn't process (NOP, etc).
            skip_insn = self.check_skip_instruction(ins_address, insn_object)
            if skip_insn == True:
                logging.trace(
                    'Instruction at '
                    + hex(ins_address)
                    + ' to be skipped.'
                )
                (ins_address, register_object) = self.update_pc_register(
                    insn_object,
                    ins_address,
                    register_object
                )
                if ins_address == None: break
                continue
            
            insn = insn_object[ins_address]['insn']
            opcode_id = insn.id

            # Debug and trace messages.
            logging.debug('------------------------------------------')
            logging.trace('memory: ' + self.print_memory(memory_map))
            logging.debug('reg: ' + self.print_memory(register_object))
            logging.debug(hex(ins_address) + '  ' + insn.mnemonic + '  ' + insn.op_str)

            # Branches require special processing.
            if opcode_id in [ARM_INS_B, ARM_INS_BX, ARM_INS_BL, ARM_INS_BLX,
                    ARM_INS_CBNZ, ARM_INS_CBZ]:
                # If BL, BLX, get return address and update Link Register.
                if opcode_id in [ARM_INS_BL, ARM_INS_BLX]:
                    link_return_address = \
                        self.all_addresses[self.all_addresses.index(ins_address) + 1]
                    register_object[ARM_REG_LR] = \
                        '{0:08x}'.format(link_return_address) 
                    
                    logging.debug(
                        'Link return address is '
                        + '{0:08x}'.format(link_return_address)
                    )
                # We process certain functions differently.
                if opcode_id == ARM_INS_BL:
                    branch_target = insn_object[ins_address]['insn'].operands[0].value.imm
                    if branch_target in common_objs.replace_functions:
                        replace_function = \
                            common_objs.replace_functions[branch_target]
                        func_type = replace_function['type']
                        if func_type == consts.FN_MEMSET:
                            memory_map = self.process_memset(
                                memory_map,
                                register_object,
                                replace_function,
                                ins_address
                            )
                            ins_address = self.get_next_address(self.all_addresses, ins_address)
                            if ins_address == None: break
                            continue
                        elif func_type == consts.FN_UDIV:
                            register_object = self.process_software_udiv(
                                register_object
                            )
                            ins_address = self.get_next_address(self.all_addresses, ins_address)
                            if ins_address == None: break
                            continue
                ins_address = self.process_branch_instruction(
                        register_object,
                        memory_map,
                        insn_object,
                        ins_address,
                        condition_flags
                    )
                if ins_address == None: break
                continue
            # Table Branch instructions require quite a bit of processing.
            elif (opcode_id in [ARM_INS_TBB, ARM_INS_TBH]):
                (ins_address, register_object, memory_map, condition_flags) = \
                    self.process_table_branch_instruction(
                        register_object,
                        memory_map,
                        condition_flags,
                        insn_object,
                        ins_address
                    )
                if ins_address == None: break
                continue
            # IT instructions.
            elif opcode_id == ARM_INS_IT:
                (ins_address, register_object, memory_map, condition_flags) = \
                    self.process_it_instruction(
                        register_object,
                        memory_map,
                        insn_object,
                        ins_address,
                        condition_flags
                    )
                if ins_address == None: break
                continue 
            # Compute the values of the registers.
            (register_object, memory_map, condition_flags) = \
                self.process_reg_values_for_instruction(
                    register_object,
                    memory_map,
                    insn_object,
                    ins_address,
                    condition_flags
                )
            (ins_address, register_object) = self.update_pc_register(
                insn_object,
                ins_address,
                register_object
            )
            if ins_address == None: break
            
            if exec_last == True:
                if pre_exec_address in end_points:
                    return (pre_exec_address, memory_map, register_object)
        return (None, None, None)
    
    def update_pc_register(self, insn_object, ins_address, register_object):
        if self.check_error == True:
            exclude_error_check = False
        else:
            exclude_error_check = True
        if utils.is_valid_code_address(ins_address, exclude_error_check) != True:
            should_update_pc_value = True
        else:
            insn = insn_object[ins_address]['insn']
            if len(insn.operands) == 0:
                should_update_pc_value = True
            else:
                if ((insn.operands[0].type == ARM_OP_REG) 
                        and (insn.operands[0].value.reg == ARM_REG_PC)):
                    should_update_pc_value = False
                elif insn.id in [ARM_INS_POP, ARM_INS_LDM, ARM_INS_LDR,
                        ARM_INS_LDRB, ARM_INS_LDRD, ARM_INS_LDREX, ARM_INS_LDREXB,
                        ARM_INS_LDREXH, ARM_INS_LDRH, ARM_INS_LDRSB, ARM_INS_LDRSH]:
                    should_update_pc_value = False
                else:
                    should_update_pc_value = True
                    
        # This is to handle the case where PC has been overwritten
        #  within the instruction.
        if should_update_pc_value == False:
            ins_address = register_object[ARM_REG_PC]
            if type(ins_address) is str:
                ins_address = int(ins_address, 16)
            return (ins_address, register_object) 

        pc_address = self.get_pc_value(ins_address)
        register_object[ARM_REG_PC] = pc_address
        ins_address = self.get_next_address(self.all_addresses, ins_address)
        
        return (ins_address, register_object)
        
    def process_branch_instruction(self, register_object, memory_map,
                                    insn_object, ins_address,
                                    condition_flags):
        insn = insn_object[ins_address]['insn']
        opcode_id = insn.id
        operands = insn.operands
        next_reg_values = register_object
        
        # Get branch target.
        if opcode_id in [ARM_INS_B, ARM_INS_BL]:
            branch_target = operands[0].value.imm
        elif opcode_id in [ARM_INS_BX, ARM_INS_BLX]:
            branch_register = operands[0].value.reg
            branch_target = self.get_register_bytes(
                next_reg_values,
                branch_register,
                'int'
            )
            
            # Do we need further processing for ARM/Thumb switch?
            if branch_target != None:
                logging.trace('Branch target is ' + hex(branch_target))
                if branch_target % 2 == 1:
                    branch_target = branch_target - 1
                    logging.trace(
                        'BX switch. New branch target is ' 
                        + hex(branch_target)
                    )
        elif opcode_id in [ARM_INS_CBZ, ARM_INS_CBNZ]:
            branch_target = operands[1].value.imm
        
        # If branch_target is denylisted, don't proceed.
        if ((branch_target in common_objs.denylisted_functions) 
                or (branch_target not in insn_object)):
            logging.trace('Branch target denylisted or not present.')
            ins_address = self.get_next_address(self.all_addresses, ins_address)
            return ins_address
            
        # Check whether we execute the branch, based on conditionals.
        # If it's a conditional branch, then we use previous condition check.
        branch_condition_satisfied = None
        if insn.cc == ARM_CC_AL: branch_condition_satisfied = True
        if (((insn.cc != ARM_CC_AL) and (insn.cc != ARM_CC_INVALID)) 
                or (opcode_id in [ARM_INS_CBZ, ARM_INS_CBNZ])):
            branch_condition_satisfied = self.check_branch_condition_satisfied(
                opcode_id,
                insn,
                condition_flags,
                next_reg_values
            )
            if ((branch_condition_satisfied == False) 
                    or (branch_condition_satisfied == None)):
                branch_target = None
            
        should_branch = False
        if branch_condition_satisfied == True:
            # Check trace path-related conditions for branching.
            (should_branch, ins_address) = self.check_should_branch(
                insn_object,
                ins_address,
                branch_target
            )
        
        # Check for conditions where we would want to execute next instruction
        #  in the event we are NOT branching.
        if (should_branch == False):
            ins_address = self.get_next_address(self.all_addresses, ins_address)
        else:
            ins_address = branch_target

        return ins_address

    def check_should_branch(self, insn_object, calling_address, branch_target):
        # The target might have been set to null on purpose, 
        #  to prevent the branch.
        if (branch_target == None): 
            logging.trace('Null target. Skipping.')
            return (False, None)

        if self.check_error == True:
            if calling_address in common_objs.errored_instructions:
                logging.trace('Errored instruction. Skipping.')
                return (False, None)
            
        logging.debug('Checking whether we should follow this branch')

        insn = insn_object[calling_address]['insn']
        opcode_id = insn.id
        
        # If it's BX LR, then it would just be returning.
        if opcode_id == ARM_INS_BX:
            return (True, branch_target)
            
        # If target not in f/w addresses, we can't proceed with branch.
        if (branch_target not in self.all_addresses):
            logging.warning(
                'Branch target '
                + hex(branch_target)
                + ' does not exist in firmware. '
                + hex(calling_address)
            )
            return (False, None)
            
        # If target is actually data, there it can't be executed.
        if insn_object[branch_target]['is_data']==True:
            logging.warning(
                'Branch target has been marked as data.'
            )
            return (False, None)

        # If current and target are equal, then it's a perpetual self-loop.
        if calling_address == branch_target:
            logging.trace('Calling address and target are equal. Skipping.')
            return (False, None)

        return (True, branch_target)

    def initialise_condition_flags(self):
        condition_flags = {
            'n': None,
            'z': None,
            'c': None,
            'v': None
        }
        return condition_flags
        
    def check_branch_condition_satisfied(self, opcode_id, instruction, flags,
                                            next_reg_values):
        if flags == None: return None
        condition = instruction.cc
        operands = instruction.operands
        is_branch_condition_satisfied = None
        # If it's CBZ/CBNZ, then the check will be different (but fairly easy).
        if ((opcode_id == ARM_INS_CBZ) or (opcode_id == ARM_INS_CBNZ)):
            (reg_value, _) = self.get_src_reg_value(
                next_reg_values, 
                operands[0], 
                'int'
            )
            if reg_value == None:
                is_branch_condition_satisfied = None
            elif reg_value == 0:
                if opcode_id == ARM_INS_CBZ:
                    is_branch_condition_satisfied = True
                else:
                    is_branch_condition_satisfied = False
            else:
                if opcode_id == ARM_INS_CBNZ:
                    is_branch_condition_satisfied = True
                else:
                    is_branch_condition_satisfied = False
            return is_branch_condition_satisfied
        # For other branch instructions.
        is_branch_condition_satisfied = self.check_condition_satisfied(
            condition,
            flags
        )
        return is_branch_condition_satisfied
        
    def check_condition_satisfied(self, condition, flags):
        logging.trace(
            'Checking whether condition satisfied for flags: '
            + str(flags)
        )
        # To bypass conditional checks, we simply return None.
        # This forces the conditional branch to execute both paths.
        if common_objs.bypass_all_conditional_checks == True:
            return None
        is_condition_satisfied = None
        if condition == ARM_CC_EQ:
            if flags['z'] == None:
                is_condition_satisfied = None
            elif flags['z'] == 1:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_NE:
            if flags['z'] == None:
                is_condition_satisfied = None
            elif flags['z'] == 0:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_HS:
            if flags['c'] == None:
                is_condition_satisfied = None
            elif flags['c'] == 1:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_LO:
            if flags['c'] == None:
                is_condition_satisfied = None
            elif flags['c'] == 0:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_MI:
            if flags['n'] == None:
                is_condition_satisfied = None
            elif flags['n'] == 1:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_PL:
            if flags['n'] == None:
                is_condition_satisfied = None
            elif flags['n'] == 0:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_VS:
            if flags['v'] == None:
                is_condition_satisfied = None
            elif flags['v'] == 1:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_VC:
            if flags['v'] == None:
                is_condition_satisfied = None
            elif flags['v'] == 0:
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_HI:
            if ((flags['c'] == None) or (flags['z'] == None)):
                is_condition_satisfied = None
            elif ((flags['c'] == 1) and (flags['z'] == 0)):
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_LS:
            if ((flags['c'] == None) or (flags['z'] == None)):
                is_condition_satisfied = None
            elif ((flags['c'] == 0) or (flags['z'] == 1)):
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_GE:
            if ((flags['n'] == None) or (flags['v'] == None)):
                is_condition_satisfied = None
            elif (flags['n'] == flags['v']):
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_LT:
            if ((flags['n'] == None) or (flags['v'] == None)):
                is_condition_satisfied = None
            elif (flags['n'] != flags['v']):
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False
        elif condition == ARM_CC_GT:
            if ((flags['z'] == None) or (flags['n'] == None) or (flags['v'] == None)):
                is_condition_satisfied = None
            elif ((flags['z'] == 0) and (flags['n'] == flags['v'])):
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False 
        elif condition == ARM_CC_LE:
            if ((flags['z'] == None) or (flags['n'] == None) or (flags['v'] == None)):
                is_condition_satisfied = None
            elif ((flags['z'] == 1) or (flags['n'] != flags['v'])):
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False 
        return is_condition_satisfied
    
    def update_condition_flags(self, condition_flags, result, carry=None, overflow=None):
        if result == None:
            condition_flags = self.initialise_condition_flags()
            return condition_flags
        if carry != None:
            condition_flags['c'] = carry
        if overflow != None:
            condition_flags['v'] = overflow
        result_in_bits = utils.get_binary_representation(result, 32)
        if result_in_bits[0] == '0':
            condition_flags['n'] = 0
        else:
            condition_flags['n'] = 1
        if '1' in result_in_bits:
            condition_flags['z'] = 0
        else:
            condition_flags['z'] = 1
        return condition_flags
            
    def check_skip_instruction(self, address, insn_object):
        if address not in insn_object:
            return True
        address_object = insn_object[address]
        if address_object['is_data'] == True:
            return True
        if address_object['insn'] == None:
            return True
        if address_object['insn'].id in [ARM_INS_NOP, ARM_INS_INVALID]:
            return True
        if address_object['insn'].id in [ARM_INS_MOV, ARM_INS_MOVW]:
            operands = address_object['insn'].operands
            op1 = operands[0].value.reg
            op2 = operands[1].value.reg
            if op1 == op2:
                return True
        return False

    #----------------  Table Branch-related ----------------
    def process_table_branch_instruction(self, register_object, memory_map,
                                            condition_flags, insn_object, 
                                            ins_address):
        # The Definitive Guide to the ARM Cortex-M3
        #  By Joseph Yiu (pg 76)
        
        insn = insn_object[ins_address]['insn']
        opcode_id = insn.id
        operands = insn.operands
        next_reg_values = register_object
        
        # We always use (current address + 4) to identify next block.
        pc_address = ins_address + 4
        
        # Get the indexing register, the value it is compared to, and the 
        #  address at which the comparison takes place.
        comp_register = common_objs.table_branches[ins_address]['comparison_register']
        comp_value = common_objs.table_branches[ins_address]['comparison_value']
        comp_address = common_objs.table_branches[ins_address]['comparison_address']

        # Get all possible branch addresses.
        table_branch_addresses = \
            common_objs.table_branches[ins_address]['table_branch_addresses']
                
        # Get address to skip to, i.e., if index is greater than comp_value.
        # This will be present in a preceding branch instruction.
        skip_address = self.get_table_skip_condition(
            comp_address,
            ins_address,
            next_reg_values,
            insn_object
        )
            
        # Get the actual value of indexing register.
        actual_value = self.get_register_bytes(
            next_reg_values,
            comp_register,
            'int'
        )
        if actual_value == None:
            branch_address = skip_address
        elif actual_value > comp_value:
            return
        else:
            branch_address = table_branch_addresses[actual_value]
            
        if branch_address not in insn_object:
            logging.critical(
                'Unable to index into table. '
                + 'Address: '
                + hex(branch_address)
            )
            return
        
        # Branch, either to address indicated by table, or to 
        #  the skip address.
        (should_branch, ins_address) = self.check_should_branch(
            insn_object,
            ins_address,
            branch_address
        )
        if should_branch != True:
            branch_address = skip_address
            
        logging.debug(
            'Table branch to ' 
            + hex(branch_address)
        )
        
        return branch_address  
            
    def get_table_branch_addresses(self, ins_address, opcode_id, num_values):
        table_branch_addresses = []
        
        pc_address = ins_address + 4

        # Set a factor of two for TBH.
        mul_factor = 1
        if opcode_id == ARM_INS_TBH:
            mul_factor = 2

        # Get all possible addresses.
        for i in range(num_values+1):
            index_address = pc_address + (mul_factor*i)
            value = utils.get_firmware_bytes(
                index_address, 
                num_bytes=mul_factor
            )
            value = int(value, 16)
            branch_address = pc_address + (2*value)
            table_branch_addresses.append(branch_address)
        
        return table_branch_addresses
    
    def get_table_skip_condition(self, start_address, end_address, next_reg_values, insn_object):
        condition = None
        branch_target = None
        
        if self.check_error == True:
            exclude_error_check = False
        else:
            exclude_error_check = True
            
        address = start_address
        while address < end_address:
            address = self.get_next_address(self.all_addresses, address)
            if utils.is_valid_code_address(address, exclude_error_check) != True:
                continue
            insn = insn_object[address]['insn']
            opcode_id = insn.id
            operands = insn.operands
            if opcode_id not in [ARM_INS_B, 
                    ARM_INS_BX, ARM_INS_CBNZ, ARM_INS_CBZ]:
                continue
            condition = insn.cc
            if opcode_id in [ARM_INS_B]:
                branch_target = operands[0].value.imm
            elif opcode_id in [ARM_INS_BX]:
                branch_register = operands[0].value.reg
                branch_target = self.get_register_bytes(
                    next_reg_values,
                    branch_register,
                    'int'
                )
            elif opcode_id in [ARM_INS_CBZ, ARM_INS_CBNZ]:
                branch_target = operands[1].value.imm
            break
        return branch_target

    # ------------------ IT instruction block handling ----------------------
    def process_it_instruction(self, register_object, memory_map,
                                insn_object, ins_address, condition_flags):
        insn = insn_object[ins_address]['insn']
        opcode_id = insn.id
        next_reg_values = register_object
        
        # Check which IT instructions to execute, depending on condition.
        branch_condition_satisfied = None
        branch_condition_satisfied = self.check_branch_condition_satisfied(
            opcode_id,
            insn,
            condition_flags,
            next_reg_values
        )
        if branch_condition_satisfied == True:
            execute_then_instructions = True
            execute_else_instructions = False
        elif branch_condition_satisfied == False:
            execute_then_instructions = False
            execute_else_instructions = True
        else:
            execute_then_instructions = True
            execute_else_instructions = True
            
        mnemonic = insn.mnemonic
        logging.debug(
            'Processing IT instruction: '
            + mnemonic
        )
        
        mnemonic = mnemonic[1:]
        number_of_conditionals = len(mnemonic)
        
        # We want to execute all the Thens together and all the Elses together.
        then_instructions = []
        else_instructions = []
        address = ins_address
        for i in range(number_of_conditionals):
            address = self.get_next_address(self.all_addresses, address)
            if mnemonic[i].lower() == 't':
                then_instructions.append(address)
            elif mnemonic[i].lower() == 'e':
                else_instructions.append(address)
        postconditional_ins_address = self.get_next_address(
            self.all_addresses,
            address
        )

        # Execute Then instructions.
        if execute_then_instructions == True:
            ins_address = self.execute_it_conditionals(
                copy.deepcopy(register_object),
                copy.deepcopy(memory_map),
                copy.deepcopy(condition_flags),
                insn_object,
                then_instructions,
                ins_address,
                postconditional_ins_address
            )
        
        # Execute Else instructions.
        if execute_else_instructions == True:
            ins_address = self.execute_it_conditionals(
                copy.deepcopy(register_object),
                copy.deepcopy(memory_map),
                copy.deepcopy(condition_flags),
                insn_object,
                else_instructions,
                ins_address,
                postconditional_ins_address
            )
            
        return (ins_address, register_object, memory_map, condition_flags)
        
    def execute_it_conditionals(self, register_object, memory_map, condition_flags,
                                    insn_object, ins_list, 
                                    original_address, branching_address):
        next_reg_values = register_object
            
        for conditional_address in ins_list:
            insn = insn_object[conditional_address]['insn']
            logging.debug('------------------------------------------')
            logging.debug('memory: ' + self.print_memory(memory_map))
            logging.debug('reg: ' + self.print_memory(next_reg_values))
            logging.debug(
                hex(conditional_address) 
                + '  ' + insn.mnemonic 
                + '  ' + insn.op_str
            )
            opcode_id = insn.id
            if opcode_id in [ARM_INS_B, ARM_INS_BX, 
                                ARM_INS_CBNZ, ARM_INS_CBZ]:            
                # The output of process_branch_instruction is a boolean,
                #  indicating whether we should execute the next instruction.
                ins_address = self.process_branch_instruction(
                    next_reg_values,
                    memory_map,
                    insn_object,
                    conditional_address,
                    condition_flags
                )
            else:
                (next_reg_values, memory_map, condition_flags) = \
                    self.process_reg_values_for_instruction(
                        next_reg_values,
                        memory_map,
                        insn_object,
                        conditional_address,
                        condition_flags
                    )
        
        if len(ins_list) > 0:
            start_branch = ins_list[-1]
        else:
            start_branch = original_address
            
        return branching_address
        
    # =======================================================================  
    # ----------------------- Instruction Processing ------------------------
    
    def process_reg_values_for_instruction(self, register_object, memory_map, 
                                insn_object, ins_address, condition_flags):
        if self.check_error == True:
            if ins_address in common_objs.errored_instructions:
                return (None, None, None)
        instruction = insn_object[ins_address]['insn']
        if instruction == None:
            return (None, None, None)
            
        # If the instruction is to be executed conditionally, first check 
        #  if the condition is satisfied.
        if condition_flags != None:
            if ((instruction.cc != ARM_CC_AL) and (instruction.cc != ARM_CC_INVALID)): 
                is_condition_satisfied = self.check_condition_satisfied(
                    instruction.cc,
                    condition_flags
                )
                if is_condition_satisfied == False:
                    return (register_object, memory_map, condition_flags)
        
        # Process instruction.        
        if instruction.id == ARM_INS_ADC:
            (register_object, condition_flags) = self.process_adc(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id in [ARM_INS_ADD, ARM_INS_ADDW]:
            (register_object, condition_flags) = self.process_add(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_ADR:
            (register_object) = self.process_adr(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_AND:
            (register_object, condition_flags) = self.process_and(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_ASR:
            (register_object, condition_flags) = self.process_asr(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_BFC:
            (register_object) = self.process_bfc(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_BFI:
            (register_object) = self.process_bfi(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_BIC:
            (register_object, condition_flags) = self.process_bic(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_CLZ:
            (register_object) = self.process_clz(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id in [ARM_INS_CMN, ARM_INS_CMP, ARM_INS_TEQ, ARM_INS_TST]:
            (condition_flags) = self.process_condition(
                ins_address,
                register_object,
                condition_flags,
                insn_object
            )
            if condition_flags == None:
                register_object = None
        elif instruction.id == ARM_INS_EOR:
            (register_object, condition_flags) = self.process_eor(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_LDM:
            (register_object, memory_map) = self.process_ldm(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags
            ) 
        elif instruction.id in [ARM_INS_LDR, ARM_INS_LDREX, 
                    ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH, 
                    ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB]:
            (register_object, memory_map) = self.process_ldr(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags
            ) 
        elif instruction.id == ARM_INS_LDRD:
            (register_object, memory_map) = self.process_ldrd(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags
            ) 
        elif instruction.id == ARM_INS_LSL:
            (register_object, condition_flags) = self.process_lsl(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_LSR:
            (register_object, condition_flags) = self.process_lsr(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_MLA:
            (register_object, condition_flags) = self.process_mla(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_MLS:
            (register_object, condition_flags) = self.process_mls(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id in [ARM_INS_MOV, ARM_INS_MOVW]:
            (register_object, condition_flags) = self.process_mov(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_MUL:
            (register_object, condition_flags) = self.process_mul(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_MVN:
            (register_object, condition_flags) = self.process_mvn(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_ORN:
            (register_object, condition_flags) = self.process_orn(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_ORR:
            (register_object, condition_flags) = self.process_orr(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_POP:
            (register_object, memory_map) = self.process_pop(
                register_object,
                ins_address,
                instruction,
                memory_map,
                condition_flags
            )
        elif instruction.id == ARM_INS_PUSH:
            (register_object, memory_map) = self.process_push(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags
            )
        elif instruction.id == ARM_INS_RBIT:
            (register_object) = self.process_rbit(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_REV:
            (register_object) = self.process_rev(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_REV16:
            (register_object) = self.process_rev16(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_ROR:
            (register_object, condition_flags) = self.process_ror(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_RRX:
            (register_object, condition_flags) = self.process_rrx(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_RSB:
            (register_object, condition_flags) = self.process_rsb(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_SBC:
            (register_object, condition_flags) = self.process_sbc(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_SDIV:
            (register_object) = self.process_sdiv(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id in [ARM_INS_STR, ARM_INS_STREX, 
                ARM_INS_STRH, ARM_INS_STREXH, 
                ARM_INS_STRB, ARM_INS_STREXB]:
            (register_object, memory_map) = self.process_str(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags
            )
        elif instruction.id == ARM_INS_STRD:
            (register_object, memory_map) = self.process_strd(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags
            )
        elif instruction.id == ARM_INS_STM:
            (register_object, memory_map) = self.process_stm(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags
            )
        elif instruction.id in [ARM_INS_SUB, ARM_INS_SUBW]:
            (register_object, condition_flags) = self.process_sub(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id in [ARM_INS_SXTB, ARM_INS_SXTH]:
            (register_object) = self.process_sxt(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_UBFX:
            (register_object) = self.process_ubfx(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_UDIV:
            (register_object) = self.process_udiv(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id in [ARM_INS_UXTB, ARM_INS_UXTH]:
            (register_object) = self.process_uxt(
                ins_address,
                instruction,
                register_object,
                condition_flags
            )
        elif instruction.id == ARM_INS_SVC:
            # We assume that all SVC calls return 0 (i.e., no error).
            register_object = self.store_register_bytes(
                register_object,
                ARM_REG_R0,
                '00000000'
            )
        else:
            if ('dsb' not in instruction.mnemonic):
                logging.trace(
                    'Unhandled instruction: '
                    + instruction.mnemonic
                )
            return (register_object, memory_map, condition_flags)
        return (register_object, memory_map, condition_flags)
    
    def process_adc(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]

        # Get values.
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None:
            return (next_reg_values, condition_flags)

        carry_in = condition_flags['c']
        if carry_in == None: carry_in = 0
        (result, carry, overflow) = binops.add_with_carry(
            start_value,
            add_value,
            carry_in
        )

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags)
        
    def process_add(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]
            
        # Get values.
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values,
            add_operand,
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            return (next_reg_values, condition_flags)
        
        (result, carry, overflow) = binops.add_with_carry(start_value, add_value)

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags)
    
    def process_adr(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)

        pc_value = self.get_mem_access_pc_value(ins_address)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )        
        if add_value == None:
            return (next_reg_values)
        
        if operands[1].subtracted == True:
            result = pc_value - add_value
        else:
            result = pc_value + add_value

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        return (next_reg_values)
        
    def process_and(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            and_operand = operands[1]
        else:
            start_operand = operands[1]
            and_operand = operands[2]

        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (and_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            and_operand, 
            'int',
            condition_flags['c']
        )
        if and_value == None:
            return (next_reg_values, condition_flags)
        
        np_dtype = utils.get_numpy_type([start_value, and_value])
        result = np.bitwise_and(
            start_value.astype(np_dtype),
            and_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_asr(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None:
            return (next_reg_values, condition_flags)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None:
            return (next_reg_values, condition_flags)
            
        (result, carry) = binops.arithmetic_shift_right(src_value, shift_value)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_bfc(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)

        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            operands[0], 
            'int'
        )
        if src_value == None:
            return (next_reg_values)
        
        (lsb, _) = self.get_src_reg_value(next_reg_values, operands[1], 'int')
        (width, _) = self.get_src_reg_value(next_reg_values, operands[2], 'int')
        bit_length = utils.get_bit_length(src_value)
        bits = utils.get_binary_representation(src_value, bit_length)
        end_idx = bit_length - lsb -1
        start_idx = bit_length - lsb - width
        
        new_bits = ''
        for i in range(bit_length):
            if i in range(start_idx, (end_idx+1)):
                new_bits += '0'
            else:
                new_bits += bits[i]

        new_value = utils.convert_bits_to_type(new_bits, type(src_value))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            new_value
        )
        return (next_reg_values)
    
    def process_bfi(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)

        (original_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[0],
            'int'
        )
        if original_value == None:
            return (next_reg_values)
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[1],
            'int'
        )
        if src_value == None:
            return (next_reg_values)
        
        (lsb, _) = self.get_src_reg_value(next_reg_values, operands[2], 'int')
        (width, _) = self.get_src_reg_value(next_reg_values, operands[3], 'int')
        bit_length = utils.get_bit_length(src_value)
        original_bits = utils.get_binary_representation(original_value, bit_length)
        src_bits = utils.get_binary_representation(src_value, bit_length)
        
        insert_bits = src_bits[(-1*width):]
        end_idx = bit_length - lsb -1
        start_idx = bit_length - lsb - width
        
        new_bits = ''
        insert_ctr = 0
        for i in range(bit_length):
            if i in range(start_idx, (end_idx+1)):
                new_bits += insert_bits[insert_ctr]
                insert_ctr += 1
            else:
                new_bits += original_bits[i]

        new_value = utils.convert_bits_to_type(new_bits, type(original_value))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            new_value
        )
        return (next_reg_values)
        
    def process_bic(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            not_operand = operands[1]
        else:
            start_operand = operands[1]
            not_operand = operands[2]

        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (not_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            not_operand, 
            'int',
            condition_flags['c']
        )
        if not_value == None:
            return (next_reg_values, condition_flags)

        np_dtype = utils.get_numpy_type([start_value, not_value])
        inverted_not_value = np.bitwise_not(
            not_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )
        result = np.bitwise_and(
            start_value.astype(np_dtype),
            inverted_not_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
    
    def process_clz(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)
        
        src_operand = operands[1]

        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None:
            return (next_reg_values)
        
        num_bits = int(len(src_value) * 2)
        result_in_bits = utils.get_binary_representation(src_value, num_bits)
        
        num_leading_zeros = 0
        for i in range(num_bits):
            if result_in_bits[i] == '0':
                num_leading_zeros += 1
            else:
                break
        result = utils.convert_type(num_leading_zeros, 'hex')
        result = result.zfill(8)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        return (next_reg_values)
        
    def process_condition(self, ins_address, register_object, condition_flags, insn_object):
        instruction = insn_object[ins_address]['insn']
        opcode_id = instruction.id
        operands = instruction.operands
        
        (operand1, _) = self.get_src_reg_value(
            register_object, 
            operands[0], 
            'int'
        )
        if operand1 == None: 
            condition_flags = self.initialise_condition_flags()
            return (condition_flags)
        (operand2, carry) = self.get_src_reg_value(
            register_object, 
            operands[1], 
            'int',
            condition_flags['c']
        )
        if operand2 == None: 
            condition_flags = self.initialise_condition_flags()
            return (condition_flags)
        
        # Test conditional.
        overflow = None
        if opcode_id == ARM_INS_CMN:
            (result, carry, overflow) = \
                binops.add_with_carry(operand1, operand2)
        elif opcode_id == ARM_INS_CMP:
            (result, carry, overflow) = \
                binops.add_with_carry(operand1, operand2, 1, sub=True)
        elif opcode_id == ARM_INS_TST:
            np_dtype = utils.get_numpy_type([operand1, operand2])
            result = np.bitwise_and(
                operand1.astype(np_dtype),
                operand2.astype(np_dtype),
                dtype=np_dtype,
                casting='safe'
            )
        elif opcode_id == ARM_INS_TEQ:
            np_dtype = utils.get_numpy_type([operand1, operand2])
            result = np.bitwise_xor(
                operand1.astype(np_dtype),
                operand2.astype(np_dtype),
                dtype=np_dtype,
                casting='safe'
            )
        # Update flags.
        condition_flags = self.update_condition_flags(
            condition_flags,
            result,
            carry,
            overflow
        )
        return (condition_flags)
        
    def process_eor(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            orr_operand = operands[1]
        else:
            start_operand = operands[1]
            orr_operand = operands[2]

        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None:
            return (next_reg_values, condition_flags)
        
        np_dtype = utils.get_numpy_type([start_value, orr_value])
        result = np.bitwise_xor(
            start_value.astype(np_dtype),
            orr_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )  

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
                
    def process_ldm(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        src_register = operands[0]
        (address, _) = self.get_src_reg_value(next_reg_values, src_register, 'int')
        if address == None: 
            ins_address = self.get_next_address(self.all_addresses, ins_address)
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                ARM_REG_PC,
                ins_address
            )
            return (next_reg_values, memory_map)
        
        for operand in operands[1:]:
            dst_operand = self.get_dst_operand(operand)
            if dst_operand == None: 
                ins_address = self.get_next_address(self.all_addresses, ins_address)
                next_reg_values = self.store_register_bytes(
                    next_reg_values,
                    ARM_REG_PC,
                    ins_address
                )
                return (next_reg_values, memory_map)
            (reg_value) = self.get_value_from_memory(
                memory_map,
                address
            )
            
            if reg_value != None:
                if reg_value.strip() == '': reg_value = None
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                dst_operand,
                reg_value
            )
            address = address + 4
            
            if operand == ARM_REG_PC:
                pc_target = reg_value
                if pc_target != None:
                    if pc_target % 2 == 1:
                        pc_target = pc_target - 1
                logging.debug('PC branch to ' + hex(pc_target))
                # Always follow branch?
                next_reg_values = self.store_register_bytes(
                    next_reg_values,
                    ARM_REG_PC,
                    pc_target
                )
                return(next_reg_values, memory_map)
                
        # Update base register if needed.
        if instruction.writeback:
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                src_register.value.reg,
                address
            )
        ins_address = self.get_next_address(self.all_addresses, ins_address)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            ARM_REG_PC,
            ins_address
        )
        return (next_reg_values, memory_map)
        
    def process_ldr(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            ins_address = self.get_next_address(self.all_addresses, ins_address)
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                ARM_REG_PC,
                ins_address
            )
            return (next_reg_values, memory_map)
        
        post_index_reg = None
        if len(operands) == 3:
            post_index_reg = operands[2]
        (src_memory_address, next_reg_values) = \
            self.get_memory_address(
                next_reg_values,
                ins_address,
                operands[1],
                instruction.writeback,
                post_index_reg
            )
        
        if src_memory_address == None:
            logging.error('Null src address: ' + hex(ins_address))
            ins_address = self.get_next_address(self.all_addresses, ins_address)
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                ARM_REG_PC,
                ins_address
            )
            return (next_reg_values, memory_map)

        # If dst_operand is PC, then it causes branch.
        if dst_operand == ARM_REG_PC:
            pc_target = self.get_register_bytes(next_reg_values, dst_operand, 'int')
            if pc_target != None:
                if pc_target % 2 == 1:
                    pc_target = pc_target -1
            logging.debug('PC branch to ' + hex(pc_target))
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                ARM_REG_PC,
                pc_target
            )
            return(next_reg_values, memory_map)
            
        logging.debug(
            'LDR address: ' + hex(src_memory_address)
        )
        
        num_bytes = 4
        if opcode_id in [ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB]:
            num_bytes = 1
        elif opcode_id in [ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH]:
            num_bytes = 2
        if src_memory_address % num_bytes != 0:
            logging.warning(
                'Misaligned LDR/H. Ins address ' 
                + hex(ins_address) 
                + ' and LDR src address '
                + hex(src_memory_address)
            )
        num_halfbytes = int(num_bytes*2)
        
        (src_value) = self.get_value_from_memory(
            memory_map,
            src_memory_address,
            unprocessed=True
        )
        logging.debug('Loaded value: ' + str(src_value))
         
        # Handle cases where None is returned (this will only happen 
        #  if dtype is not hex.
        if src_value != None:
            if src_value.strip() == '': src_value = None
        if src_value == None:
            logging.warning(
                'LDR destination not present in memory: '
                + hex(src_memory_address)
            )
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                dst_operand,
                src_value
            )
            ins_address = self.get_next_address(self.all_addresses, ins_address)
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                ARM_REG_PC,
                ins_address
            )
            return (next_reg_values, memory_map)
                    
        # Get the required bytes.
        src_value = src_value.zfill(8)
        
        src_value = src_value[(-1*num_halfbytes):]

        if ((opcode_id == ARM_INS_LDRB) 
                or (opcode_id == ARM_INS_LDRH)
                or (opcode_id == ARM_INS_LDREXB) 
                or (opcode_id == ARM_INS_LDREXH)):
            src_value = src_value.zfill(8)
        elif ((opcode_id == ARM_INS_LDRSB) or (opcode_id == ARM_INS_LDRSH)):
            src_value = binops.sign_extend(src_value)
        
        logging.trace('Value to load: ' + str(src_value))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            src_value
        )
        ins_address = self.get_next_address(self.all_addresses, ins_address)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            ARM_REG_PC,
            ins_address
        )
        return (next_reg_values, memory_map)
    
    def process_ldrd(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        dst_operand1 = self.get_dst_operand(operands[0])
        if dst_operand1 == None: 
            return (next_reg_values, memory_map)
        dst_operand2 = self.get_dst_operand(operands[1])
        if dst_operand2 == None: 
            return (next_reg_values, memory_map)
        
        post_index_reg = None
        if len(operands) == 4:
            post_index_reg = operands[3]
        (src_memory_address, next_reg_values) = \
            self.get_memory_address(
                next_reg_values,
                ins_address,
                operands[2],
                instruction.writeback,
                post_index_reg
            )
        
        if src_memory_address == None:
            logging.error('Null src address: ' + hex(ins_address))
            return (next_reg_values, memory_map)
            
        #Operand1.
        logging.debug(
            'LDR address: ' + hex(src_memory_address)
        )        
        (src_value1) = self.get_value_from_memory(
            memory_map,
            src_memory_address,
            unprocessed=True,
            num_bytes=4
        )
        if src_value1 != None:
            if src_value1.strip() == '': src_value1 = None
        if src_value1 == None:
            logging.warning(
                'LDR destination not present in memory: '
                + hex(src_memory_address)
            )
        else:
            # Get the required bytes.
            src_value1 = src_value1.strip().zfill(8)

        logging.trace('Value to load: ' + str(src_value1))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand1,
            src_value1
        )
        
        # Operand2
        logging.debug(
            'LDR address: ' + hex(src_memory_address+4)
        )  
        (src_value2) = self.get_value_from_memory(
            memory_map,
            src_memory_address+4,
            unprocessed=True,
            num_bytes=4
        )
        if src_value2 != None:
            if src_value2.strip() == '': src_value2 = None
        if src_value2 == None:
            logging.warning(
                'LDR destination not present in memory: '
                + hex(src_memory_address+4)
            )
        else:
            # Get the required bytes.
            src_value2 = src_value2.strip().zfill(8)
        
        logging.trace('Value to load: ' + str(src_value2))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand2,
            src_value2
        )
        return (next_reg_values, memory_map)
        
    def process_lsl(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None:
            return (next_reg_values, condition_flags)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None:
            return (next_reg_values, condition_flags)
            
        (result, carry) = binops.logical_shift_left(src_value, shift_value)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_lsr(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None:
            return (next_reg_values, condition_flags)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None:
            return (next_reg_values, condition_flags)
            
        (result, carry) = binops.logical_shift_right(src_value, shift_value)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_mla(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        operand1 = operands[1]
        operand2 = operands[2]
        accumulateop = operands[3]

        (value1, _) = self.get_src_reg_value(next_reg_values, operand1, 'int')
        if value1 == None:
            return (next_reg_values, condition_flags)
        (value2, _) = self.get_src_reg_value(next_reg_values, operand2, 'int')
        if value2 == None:
            return (next_reg_values, condition_flags)
        (accumulate, _) = self.get_src_reg_value(next_reg_values, accumulateop, 'int')
        if accumulate == None:
            return (next_reg_values, condition_flags)

        value1 = getattr(value1, "tolist", lambda: value1)()
        value2 = getattr(value2, "tolist", lambda: value2)()
        accumulate = getattr(accumulate, "tolist", lambda: accumulate)()
        mul_value = value1 * value2
        mul_value = mul_value + accumulate
        mul_value = '{0:08x}'.format(mul_value)
        mul_value = mul_value.zfill(8)
        result = mul_value[-8:]

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result
            )
        return (next_reg_values, condition_flags)
        
    def process_mls(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        operand1 = operands[1]
        operand2 = operands[2]
        accumulateop = operands[3]

        (value1, _) = self.get_src_reg_value(next_reg_values, operand1, 'int')
        if value1 == None:
            return (next_reg_values, condition_flags)
        (value2, _) = self.get_src_reg_value(next_reg_values, operand2, 'int')
        if value2 == None:
            return (next_reg_values, condition_flags)
        (accumulate, _) = self.get_src_reg_value(next_reg_values, accumulateop, 'int')
        if accumulate == None:
            return (next_reg_values, condition_flags)

        value1 = getattr(value1, "tolist", lambda: value1)()
        value2 = getattr(value2, "tolist", lambda: value2)()
        accumulate = getattr(accumulate, "tolist", lambda: accumulate)()
        mul_value = value1 * value2
        mul_value = accumulate - mul_value 
        mul_value = np.int32(mul_value)
        mul_value = '{0:08x}'.format(mul_value)
        mul_value = mul_value.zfill(8)
        result = mul_value[-8:]

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        return (next_reg_values, condition_flags)
        
    def process_mov(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        if len(operands) != 2:
            logging.error('More than 2 ops ' + instruction.op_str)
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)

        (result, carry) = self.get_src_reg_value(next_reg_values, operands[1])
        if operands[1].type == ARM_OP_REG: carry = None
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
    
    def process_mul(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            operand1 = operands[0]
            operand2 = operands[1]
        else:
            operand1 = operands[1]
            operand2 = operands[2]

        (value1, _) = self.get_src_reg_value(next_reg_values, operand1, 'int')
        if value1 == None:
            return (next_reg_values, condition_flags)
        (value2, _) = self.get_src_reg_value(next_reg_values, operand2, 'int')
        if value2 == None:
            return (next_reg_values, condition_flags)

        value1 = getattr(value1, "tolist", lambda: value1)()
        value2 = getattr(value2, "tolist", lambda: value2)()
        mul_value = value1 * value2
        mul_value = '{0:08x}'.format(mul_value)
        mul_value = mul_value.zfill(8)
        result = mul_value[-8:]

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result
            )
        return (next_reg_values, condition_flags)
    
    def process_mvn(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        if len(operands) != 2:
            logging.error('More than 2 ops ' + instruction.op_str)
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)

        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int',
            condition_flags['c']
        )
        if src_value == None:
            return (next_reg_values, condition_flags)
        
        bit_length = utils.get_bit_length(src_value)
        mult = 0xFFFFFFFF
        if bit_length == 8:
            mult = 0xFF
        elif bit_length == 16:
            mult = 0xFFFF
        result = (~src_value & mult)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_orn(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            orr_operand = operands[1]
        else:
            start_operand = operands[1]
            orr_operand = operands[2]

        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None:
            return (next_reg_values, condition_flags)
        
        np_dtype = utils.get_numpy_type([start_value, orr_value])
        orr_value = np.bitwise_not(
            orr_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )
        result = np.bitwise_or(
            start_value.astype(np_dtype),
            orr_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )  

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_orr(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            orr_operand = operands[1]
        else:
            start_operand = operands[1]
            orr_operand = operands[2]
            
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None:
            return (next_reg_values, condition_flags)
        
        np_dtype = utils.get_numpy_type([start_value, orr_value])
        result = np.bitwise_or(
            start_value.astype(np_dtype),
            orr_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )  

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_pop(self, current_reg_values, ins_address,
                        instruction, memory_map, condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands

        current_sp = self.get_register_bytes(next_reg_values, ARM_REG_SP, 'int')
        address = current_sp
        new_sp = current_sp + (4*len(operands))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            ARM_REG_SP,
            new_sp
        )
        
        for operand in operands:
            mem_bytes = self.get_memory_bytes(memory_map, address)
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                operand.value.reg,
                self.get_memory_bytes(memory_map, address)
            )
            memory_map.pop(address, None)
            address += 4
            
        # Sort the stack.
        memory_map = {key:memory_map[key] for key in sorted(memory_map.keys())}

        last_register = operands[-1].value.reg
        if last_register == ARM_REG_PC:
            pc_target = self.get_register_bytes(next_reg_values, last_register, 'int')
            if pc_target != None:
                if pc_target % 2 == 1:
                    pc_target = pc_target - 1
            logging.debug('Returning to ' + str(pc_target) + ' (POP PC)')
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                ARM_REG_PC,
                pc_target
            )
            return (next_reg_values, memory_map)
        ins_address = self.get_next_address(self.all_addresses, ins_address)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            ARM_REG_PC,
            ins_address
        )
        return (next_reg_values, memory_map)
    
    def process_push(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        current_sp = self.get_register_bytes(next_reg_values, ARM_REG_SP, 'int')
        address = current_sp - (4*len(operands))
        
        for operand in operands:
            stack_bytes = \
                self.get_register_bytes(next_reg_values, operand.value.reg)
            memory_map = self.store_memory_bytes(
                memory_map,
                address,
                stack_bytes
            )
            address += 4
            
        new_sp = current_sp - (4*len(operands))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            ARM_REG_SP,
            new_sp
        )
        
        # Sort the stack.
        memory_map = {key:memory_map[key] for key in sorted(memory_map.keys())}

        return (next_reg_values, memory_map)
        
    def process_rbit(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)

        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[1])
        if src_value == None:
            return (next_reg_values)
        
        # reversed_bits.
        src_bits = utils.get_binary_representation(src_value, 32)
        reversed_bits = src_bits[::-1]
            
        reversed_bytes = utils.convert_bits_to_type(reversed_bits, 'hex')
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            reversed_bytes
        )
        return (next_reg_values)
        
    def process_rev(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)

        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[1], 'hex')
        if src_value == None:
            return (next_reg_values)
        
        # reversed_bits.
        if len(src_value) != 8:
            logging.error(
                'Reverse operand is not the correct length'
            )
            src_value = src_value.zfill(8)
            
        reversed_bytes = src_value[6:8] \
                         + src_value[4:6] \
                         + src_value[2:4] \
                         + src_value[0:2]
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            reversed_bytes
        )
        return (next_reg_values)
        
    def process_rev16(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)

        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[1], 'hex')
        if src_value == None:
            return (next_reg_values)
        
        # reversed_bits.
        if len(src_value) != 8:
            logging.error(
                'Reverse operand is not the correct length'
            )
            src_value = src_value.zfill(8)
            
        reversed_bytes = src_value[2:4] \
                         + src_value[0:2] \
                         + src_value[6:8] \
                         + src_value[4:6] 
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            reversed_bytes
        )
        return (next_reg_values)
        
    def process_ror(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None:
            return (next_reg_values, condition_flags)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None:
            return (next_reg_values, condition_flags)
            
        (result, carry) = binops.rotate_right(src_value, shift_value)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_rrx(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)

        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )
        if src_value == None:
            return (next_reg_values, condition_flags)
        
        # Process shift.
        (result, carry) = binops.rotate_right_with_extend(
            src_value,
            condition_flags['c']
        )
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags)
        
    def process_rsb(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]

        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None:
            return (next_reg_values, condition_flags)

        (result, carry, overflow) = \
            binops.add_with_carry(add_value, start_value, 1, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags)
        
    def process_sbc(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]

        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None:
            return (next_reg_values, condition_flags)

        carry_in = condition_flags['c']
        if carry_in == None: carry_in = 0
        (result, carry, overflow) = \
            binops.add_with_carry(start_value, add_value, carry_in, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags)
        
    def process_sbfx(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)

        (src_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[1]
        )
        if src_value == None:
            return (next_reg_values)
        
        (lsb, _) = self.get_src_reg_value(next_reg_values, operands[2], 'int')
        (width, _) = self.get_src_reg_value(next_reg_values, operands[3], 'int')
        src_bits = utils.get_binary_representation(src_value, 32)
        msb = lsb + width - 1
        new_bits = src_bits[msb:lsb]
        top_bit = new_bits[0]
        if msb <= 31:
            extended_bits = ''
            for i in range(32):
                extended_bits += top_bit
            extended_bits += new_bits
            new_bits = extended_bits[-32:]
            
        new_value = utils.convert_bits_to_type(new_bits, 'hex')
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            new_value,
            True
        )
        return (next_reg_values)
        
    def process_sdiv(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)
        
        if len(operands) == 2:
            numerator_operand = operands[0]
            denominator_operand = operands[1]
        else:
            numerator_operand = operands[1]
            denominator_operand = operands[2]

        (numerator, _) = self.get_src_reg_value(
            next_reg_values, 
            numerator_operand, 
            'int',
            signed=True
        )
        if numerator == None: 
            return (next_reg_values)
        (denominator, _) = self.get_src_reg_value(
            next_reg_values, 
            denominator_operand, 
            'int',
            signed=True
        )
        if denominator == None: 
            return (next_reg_values)
        if denominator == 0:
            value = 0
        else:
            value = numerator//denominator
        value = np.int32(value)
        value = '{0:08x}'.format(value)
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            value,
            True
        )
        return (next_reg_values)
        
    def process_stm(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands

        dst_register = operands[0]
        (address, _) = self.get_src_reg_value(next_reg_values, dst_register, 'int')
        if address == None: 
            return (next_reg_values, memory_map)
        
        for operand in operands[1:]:
            (src_value, _) = self.get_src_reg_value(next_reg_values, operand)
            memory_map = self.store_value_to_memory(
                src_value,
                address,
                memory_map,
                4
            )
            address = address + 4

        if instruction.writeback:
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                dst_register.value.reg,
                address
            )
        return (next_reg_values, memory_map)
        
    def process_str(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[0], 'hex')
        if src_value == None: 
            return (next_reg_values, memory_map)
        
        num_bytes = 4
        if opcode_id in [ARM_INS_STRB, ARM_INS_STREXB]:
            src_value = src_value[-2:]
            num_bytes = 1
        elif opcode_id in [ARM_INS_STRH, ARM_INS_STREXH]:
            src_value = src_value[-4:]
            num_bytes = 2
        logging.trace('Value to store: ' + str(src_value))

        post_index_reg = None
        if len(operands) == 3:
            post_index_reg = operands[2]
        (dst_memory_address, next_reg_values) = \
            self.get_memory_address(
                next_reg_values,
                ins_address,
                operands[1],
                instruction.writeback,
                post_index_reg
            )
        if dst_memory_address == None:
            return (next_reg_values, memory_map)
            
        memory_map = self.store_value_to_memory(
                src_value,
                dst_memory_address,
                memory_map,
                num_bytes
            )
            
        if opcode_id in [ARM_INS_STREX, ARM_INS_STREXB, ARM_INS_STREXH]:
            # We assume the executing processor always has exclusive access 
            #  to the memory addressed.
            new_reg_value = '00000000'
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                operands[0].value.reg,
                new_reg_value
            )
            
        return (next_reg_values, memory_map)
        
    def process_strd(self, ins_address, instruction, current_reg_values, 
                            memory_map, condition_flags):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        (src_value1, _) = self.get_src_reg_value(next_reg_values, operands[0], 'hex')
        (src_value2, _) = self.get_src_reg_value(next_reg_values, operands[1], 'hex')
        if ((src_value1 == None) and (src_value2 == None)):
            return (next_reg_values, memory_map)
            
        logging.trace(
            'Values to store: ' 
            + str(src_value1) 
            + ' and ' 
            + str(src_value2)
        )

        post_index_reg = None
        if len(operands) == 4:
            post_index_reg = operands[3]
        (dst_memory_address, next_reg_values) = \
            self.get_memory_address(
                next_reg_values,
                ins_address,
                operands[2],
                instruction.writeback,
                post_index_reg
            )
        if dst_memory_address == None:
            return (next_reg_values, memory_map)
            
        # Store first value.
        memory_map = self.store_value_to_memory(
                src_value1,
                dst_memory_address,
                memory_map,
                4
            )
        # Store second value.
        memory_map = self.store_value_to_memory(
                src_value2,
                dst_memory_address + 4,
                memory_map,
                4
            )
            
        return (next_reg_values, memory_map)
        
    def process_sub(self, ins_address, instruction, current_reg_values, 
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]

        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None:
            return (next_reg_values, condition_flags)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None:
            return (next_reg_values, condition_flags)
        
        (result, carry, overflow) = \
            binops.add_with_carry(start_value, add_value, 1, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if (instruction.update_flags == True):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags)

    def process_sxt(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)
        
        src_operand = operands[1]

        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None:
            return (next_reg_values)
        
        # This is to make sure we get the correct bytes.
        src_value = src_value.zfill(8)

        if opcode_id == ARM_INS_SXTB:
            src_value = src_value[-2:]
        elif opcode_id == ARM_INS_SXTH:
            src_value = src_value[-4:]
        
        # This is the actual extension.
        extended_value = binops.sign_extend(src_value)
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            extended_value
        )
        return (next_reg_values)
        
    def process_ubfx(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)
 
        (src_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[1]
        )
        if src_value == None: 
            return (next_reg_values)
        
        (lsb, _) = self.get_src_reg_value(next_reg_values, operands[2], 'int')
        (width, _) = self.get_src_reg_value(next_reg_values, operands[3], 'int')
        src_bits = utils.get_binary_representation(src_value, 32)
        msb = lsb + width - 1
        new_bits = src_bits[msb:lsb]
        if msb <= 31:
            new_bits = new_bits.zfill(32)
            
        new_value = utils.convert_bits_to_type(new_bits, 'hex')
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            new_value,
            True
        )
        return (next_reg_values)
            
    def process_udiv(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)
        
        if len(operands) == 2:
            numerator_operand = operands[0]
            denominator_operand = operands[1]
        else:
            numerator_operand = operands[1]
            denominator_operand = operands[2]

        (numerator, _) = self.get_src_reg_value(
            next_reg_values, 
            numerator_operand, 
            'int'
        )
        if numerator == None: 
            return (next_reg_values)
        (denominator, _) = self.get_src_reg_value(
            next_reg_values, 
            denominator_operand, 
            'int'
        )
        if denominator == None: 
            return (next_reg_values)
        if denominator == 0:
            value = 0
        else:
            value = numerator//denominator
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            value,
            True
        )
        return (next_reg_values)
            
    def process_uxt(self, ins_address, instruction, current_reg_values,
                            condition_flags):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values)
        
        src_operand = operands[1]

        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None: 
            return (next_reg_values)
        
        # This is to make sure we get the correct bytes.
        src_value = src_value.zfill(8)

        if opcode_id == ARM_INS_UXTB:
            src_value = src_value[-2:]
        elif opcode_id == ARM_INS_UXTH:
            src_value = src_value[-4:]
        
        # This is the actual extension.
        extended_value = src_value.zfill(8)
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            extended_value,
            True
        )
        return (next_reg_values)

    def get_dst_operand(self, operand):
        # This should never actually happen.
        if operand.type != ARM_OP_REG:
            logging.critical('Non-register destination operand!')
            return None
        dst_operand = operand.value.reg
        return dst_operand
        
    def get_src_reg_value(self, current_reg_values, src_operand, dtype='hex',
                            carry_in=None, signed=None):
        if src_operand.type == ARM_OP_IMM:
            src_value = src_operand.value.imm
            if src_value < 0:
                src_value = '{:08x}'.format(src_value & (2**32-1))
            else:
                src_value = np.uint32(src_value)
                src_value = '{:08x}'.format(src_value & (2**32-1))
        elif src_operand.type == ARM_OP_REG:
            src_register = src_operand.value.reg
            if current_reg_values[src_register] == None:
                return (None, None)
            src_value = self.get_register_bytes(
                current_reg_values,
                src_register,
                dtype
            )
            if src_register == ARM_REG_PC:
                if type(src_value) is int:
                    src_value = np.uint32(src_value)
        else:
            logging.critical('Non imm/reg src ' + instruction.op_str)
            return (None, None)

        if carry_in == None:
            src_value = utils.convert_type(src_value, dtype, signed=signed)        
            return (src_value, carry_in)
        
        carry = carry_in
        if src_operand.shift.value != 0:
            src_value = utils.convert_type(src_value, 'int', signed=signed)
            shift_value = src_operand.shift.value
            shift_type = src_operand.shift.type
            if shift_type == ARM_SFT_ASR:
                (src_value, carry) = binops.arithmetic_shift_right(src_value, shift_value)
            elif shift_type == ARM_SFT_LSL:
                (src_value, carry) = binops.logical_shift_left(src_value, shift_value)
            elif shift_type == ARM_SFT_LSR:
                (src_value, carry) = binops.logical_shift_right(src_value, shift_value)
            elif shift_type == ARM_SFT_ROR:
                (src_value, carry) = binops.rotate_right(src_value, shift_value)
            elif shift_type == ARM_SFT_RRX:
                (src_value, carry) = binops.rotate_right_with_extend(
                    src_value, carry_in
                )
        else:
            carry = carry_in
        src_value = utils.convert_type(src_value, dtype, signed=signed)        
        return (src_value, carry)
        
    def get_shift_value(self, current_reg_values, shift_operand):
        if shift_operand.type == ARM_OP_IMM:
            shift_value = shift_operand.value.imm
        elif shift_operand.type == ARM_OP_REG:
            src_register = shift_operand.value.reg
            if current_reg_values[src_register] == None:
                return None
            shift_value = self.get_register_bytes(
                current_reg_values,
                src_register,
                'int'
            )
        else:
            logging.critical('Non imm src ' + instruction.op_str)
        return shift_value
        
    def get_memory_address(self, current_reg_values, ins_address, operand, 
                                bool_wback, post_index_reg=None, pc_value=None):
        next_reg_values = current_reg_values
        base_register = operand.value.mem.base
        index_register = operand.value.mem.index
        offset = operand.value.mem.disp 
        lshift = operand.value.mem.lshift
        subtract = operand.subtracted
        src_memory_address = None
        base_register_new_value = None
        
        # If base reg is PC, then don't use the PC register value.
        #  We need to compute it according to certain rules.
        if base_register == ARM_REG_PC:
            if pc_value != None:
                base_value = pc_value
            else:
                base_value = self.get_mem_access_pc_value(ins_address)
        else:
            # If we haven't populated base register in preceding instructions,
            #  then we won't be able to proceed.
            if current_reg_values[base_register] == None:
                return(src_memory_address, next_reg_values)
            base_value = self.get_register_bytes(
                current_reg_values,
                base_register,
                'int'
            )
        
        # Register offset.
        if index_register != 0:
            if current_reg_values[index_register] == None:
                logging.error(
                    'Index register '
                    + str(index_register)
                    + ' is None. Cannot compute memory address.'
                )
                return(src_memory_address, next_reg_values)
                
            offset_value = self.get_register_bytes(
                current_reg_values,
                index_register,
                'int'
            )
            (offset_value, _) = binops.logical_shift_left(offset_value, lshift)
        # Immediate offset.
        else:
            offset_value = offset
        if subtract == True:
            src_memory_address = base_value - offset_value
        else:
            src_memory_address = base_value + offset_value
            
        if bool_wback == True:
            register_wback = src_memory_address
            if post_index_reg != None:
                (post_index_val, _) = self.get_src_reg_value(
                    next_reg_values,
                    post_index_reg,
                    'int'
                )
                register_wback += post_index_val
            if base_register != ARM_REG_PC:
                next_reg_values = self.store_register_bytes(
                    next_reg_values,
                    base_register,
                    '{0:08x}'.format(register_wback)
                )

        return(src_memory_address, next_reg_values)
       
    def get_pc_value(self, ins_address):
        pc_address_1 = self.get_next_address(self.all_addresses, ins_address)
        pc_address = self.get_next_address(self.all_addresses, pc_address_1)
        return pc_address
        
    def get_mem_access_pc_value(self, ins_address):
        curr_pc_value = ins_address + 4
        
        # When the PC is used as a base register for addressing operations 
        #  (i.e. adr/ldr/str/etc.) it is always the word-aligned value 
        #  that is used, even in Thumb state. 
        # So, whilst executing a load instruction at 0x159a, 
        #  the PC register will read as 0x159e, 
        #  but the base address of ldr...[pc] is Align(0x159e, 4), 
        #  i.e. 0x159c.
        # Ref: https://stackoverflow.com/a/29588678
        if ((curr_pc_value % 4) != 0):
            aligned_pc_value = curr_pc_value - (curr_pc_value % 4)
            curr_pc_value = aligned_pc_value
        return curr_pc_value

    # =======================================================================  
    #---------------------------- Memory Operations -------------------------
    
    def get_address_type(self, address, memory_map=None):
        data_region = list(common_objs.data_region.keys())
        data_region.sort()
        if len(data_region) > 0:
            start_data_region = data_region[0]
            end_data_region = data_region[-1]
            if ((address >= start_data_region) 
                    and (address <= end_data_region)):
                return consts.ADDRESS_DATA
        # Firmware.
        start_fw_address = self.all_addresses[0]
        # Don't use common_objs.code_end_address as end of f/w address
        #  because .rodata might be part of the remaining file.
        end_fw_address = self.all_addresses[-1] 
        if ((address >= start_fw_address) 
                and (address <= end_fw_address)):
            return consts.ADDRESS_FIRMWARE
        # Default to RAM.
        return consts.ADDRESS_RAM
    
    def get_register_bytes(self, registers, address, dtype='hex'):
        value = None
        if address in registers:
            value = registers[address]
            
        # Type conversion
        value = utils.convert_type(value, dtype)
        return value
        
    def get_value_from_memory(self, memory_map, address, 
                                num_bytes=4, dtype='hex', unprocessed=False):
        address_type = self.get_address_type(address, memory_map)
        src_value = None
        if address_type == consts.ADDRESS_DATA:
            src_value = self.get_data_bytes(address, num_bytes, dtype)
        elif address_type == consts.ADDRESS_FIRMWARE:
            src_value = utils.get_firmware_bytes(address, num_bytes, dtype)
        else:
            src_value = self.get_memory_bytes(
                memory_map,
                address,
                num_bytes,
                dtype,
                unprocessed
            )
            
        # If we get unusable values, return all-0s.
        # This is EXTREMELY IMPORTANT! DO NOT MODIFY OR DELETE!
        if (((src_value == None) 
                or (src_value == '')) 
                and (dtype == 'hex')):
            logging.debug('Returned value is empty or None.')
            src_value = ''.zfill(num_bytes*2)
        return (src_value)
        
    def get_data_bytes(self, address, num_bytes=4, dtype='hex',
            endian=common_objs.endian):
        logging.debug(
            'Getting ' 
            + str(num_bytes)
            + ' bytes from data region '
            + ' starting at memory address '
            + hex(address)
        )
        offset = address - common_objs.data_segment_start_address
        address_in_firmware = \
            common_objs.data_segment_start_firmware_address + offset
        logging.debug(
            'Address '
            + hex(address)
            + ' translates to '
            + hex(address_in_firmware)
            + ' in firmware.'
        )
        value = utils.get_firmware_bytes(
                    address_in_firmware, 
                    num_bytes,
                    endian='big'
                )
        if endian == 'little':
            value = utils.reverse_bytes(utils.convert_type(value, 'bytes'))
            value = utils.convert_type(value, 'hex')
        logging.debug('Read bytes ' + value)
        # Type conversion.
        value = utils.convert_type(value, dtype)
        return value
        

    def get_memory_bytes(self, memory_map, address, num_bytes=4, dtype='hex', 
                            unprocessed=False, endian=common_objs.endian):
        # If we want raw values, then use this.
        if unprocessed == True:
            value = self.get_unprocessed_memory_bytes(
                memory_map,
                address,
                num_bytes,
                dtype
            )
            return value
        
        logging.debug(
            'Reading ' + str(num_bytes) + ' bytes '
            + 'from address ' + '{0:08x}'.format(address) 
            + ' in memory'
        )
        # If the values are required by register_evaluator.
        if (num_bytes == 4):
            if (address%4 != 0):
                logging.error('Misaligned word.')
            value = self.get_memory_word(memory_map, address, endian)
        elif (num_bytes == 2):
            if (address%2 != 0):
                logging.error('Misaligned word.')
            value = self.get_memory_halfword(memory_map, address, endian)
        elif (num_bytes == 1):
            if address not in memory_map:
                value = '00'
            else:
                value = memory_map[address]
        else:
            logging.error('Invalid number of bytes.')
        value = utils.convert_type(value, dtype)
        return value
        
    def get_memory_word(self, memory_map, address, endian=common_objs.endian):
        logging.debug(
            'Reading word '
            + 'from address ' + '{0:08x}'.format(address) 
            + ' in memory'
        )
        if endian == None: endian = common_objs.endian
        out_value = ''
        for i in range(4):
            if (address+i) in memory_map:
                concat_value = memory_map[address+i]
            else:
                concat_value = '00'
            if endian == 'little':
                out_value = concat_value + out_value
            else:
                out_value = out_value + concat_value
        return out_value
        
    def get_memory_halfword(self, memory_map, address, endian=common_objs.endian):
        logging.debug(
            'Reading halfword '
            + 'from address ' + '{0:08x}'.format(address) 
            + ' in memory'
        )
        if endian == None: endian = common_objs.endian
        out_value = ''
        for i in range(2):
            if (address+i) in memory_map:
                concat_value = memory_map[address+i]
            else:
                concat_value = '00'
            if endian == 'little':
                out_value = concat_value + out_value
            else:
                out_value = out_value + concat_value
        return out_value
    
    def get_unprocessed_memory_bytes(self, memory_map, address, 
                                        num_bytes=4, dtype='hex'):
        logging.debug(
            'Reading ' + str(num_bytes) + ' unprocessed bytes '
            + 'from address ' + '{0:08x}'.format(address) 
            + ' in memory'
        )
        out_value = ''
        for i in range(num_bytes):
            if (address+i) in memory_map:
                out_value = memory_map[address+i] + out_value
            else:
                break
        return out_value
    
    def available_bytes_at_memory_location(self, memory_map, address, dtype):
        temp_bytes = 0
        if address in memory_map:
            temp_value = memory_map[address]
            if temp_value != None:
                if dtype == 'hex':
                    temp_value = utils.convert_type(temp_value, 'hex')
                    temp_halfbytes = len(temp_value)
                    temp_bytes = int(temp_halfbytes/2)
        return temp_bytes

    def store_register_bytes(self, registers, address, value, force_word_length=False):
        if address not in registers:
            return registers
        
        value = utils.convert_type(value, 'hex')
        if force_word_length == True: 
            value = value.zfill(8)
            value = value[-8:]
        registers[address] = value
        return registers
        
    def store_value_to_memory(self, value, address, memory_map, num_bytes):
        value = utils.convert_type(value, 'hex')
        if value == None:
            value = '00' * num_bytes
        value = value.zfill(2*num_bytes)

        for i in range(num_bytes):
            byte0 = (i*-2) - 1
            byte1 = (i*-2) - 2
            concat = value[byte1] + value[byte0]
            memory_map[address+i] = concat
        
        logging.debug(
            'Storing data: ' 
            + str(value) 
            + ' to memory address: ' 
            + hex(address)
        )
        return memory_map

    def store_memory_bytes(self, memory_map, address, value, 
                               force_word_length=False):
        value = utils.convert_type(value, 'hex')
        if force_word_length == True: value = value.zfill(8)
        
        if value == None:
            memory_map[address] = '00'
            return memory_map
            
        if len(value) % 2 != 0:
            value = '0' + value
        num_bytes = int(len(value)/2)
        for i in range(num_bytes):
            byte0 = (i*-2) - 1
            byte1 = (i*-2) - 2
            concat = value[byte1] + value[byte0]
            memory_map[address+i] = concat
        
        logging.debug(
            'Storing data: ' 
            + str(value) 
            + ' to memory address: ' 
            + hex(address)
        )                 
        return memory_map

    def process_memset(self, memory_map, register_object, memset_obj, address):
        logging.debug('Call to memset identified.')
        ptr_address = register_object[memset_obj['pointer']]
        if memset_obj['fixed_value'] != None:
            value = memset_obj['fixed_value']
        else:
            value = register_object[memset_obj['value']]
        length = register_object[memset_obj['length']]
        if ((ptr_address == None)
                or (value == None)
                or (length == None)):
            logging.warning('At least one of the 3 parameters is null.')
            return memory_map
        if type(length) == str:
            length = int(length, 16)
        if length == 0:
            logging.warning('memset len specified as 0 at ' + hex(address))
            return memory_map
        # We don't want to create huge memory maps,
        #  so process only if length is lower than a certain value.
        # We choose the length as the maximum length specified in 
        #  COI definitions.
        if length > 125:
            logging.debug(
                'Over-large value for length '
                + str(length)
            )
            return memory_map
        value = utils.convert_type(value, 'hex')
        value = value.zfill(8)
        if value[0:6] != '000000':
            return memory_map
        value = value[-2:]
        if type(ptr_address) == str:
            ptr_address = int(ptr_address, 16)
            
        address = ptr_address
        while length > 0:
            if length < 4:
                fill_length = length
            else:
                fill_length = 4
            mul_value = ''
            for i in range(fill_length):
                mul_value += value
            memory_map = self.store_memory_bytes(
                memory_map,
                address,
                mul_value
            )
            address = address + 4
            length = length - 4
        return memory_map
        
    def process_software_udiv(self, register_object):
        numerator = utils.convert_type(register_object[ARM_REG_R0], 'int')
        denominator = utils.convert_type(register_object[ARM_REG_R1], 'int')
        if ((numerator == None) or (denominator == None)):
            return register_object
        if denominator == 0:
            register_object[ARM_REG_R1] = utils.convert_type(numerator, 'hex')
            register_object[ARM_REG_R0] = '00000000'
            return register_object
        quotient = numerator//denominator
        remainder = numerator%denominator
        register_object[ARM_REG_R0] = utils.convert_type(quotient, 'hex')
        register_object[ARM_REG_R1] = utils.convert_type(remainder, 'hex')
        return register_object
        
    # =======================================================================  
    #-------------------------- Utility functions ---------------------------

    def get_next_address(self, address_obj, ins_address):
        if address_obj == None: return None
        if ins_address == None: return None
        
        if type(address_obj) is dict:
            address_obj = list(address_obj.keys())
            address_obj.sort()
            
        if ins_address not in address_obj: return None
        
        # Find index of the address and get next one up.
        if (address_obj.index(ins_address)) < (len(address_obj) - 1):
            next_address = address_obj[address_obj.index(ins_address) + 1]
        else:
            next_address = None
        return next_address    
        
    def print_memory(self, memory):
        # Sort memory obj.
        memory = {key:memory[key] for key in sorted(memory.keys())}
        string_mem = '{'
        for address in memory:
            string_mem += hex(address)
            string_mem += ':'
            value = utils.convert_type(memory[address], 'hex')
            string_mem += str(value)
            string_mem += ','
        string_mem += '}'
        return string_mem
