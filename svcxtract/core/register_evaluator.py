import os
import sys
import copy
import json
import struct
import timeit
import logging
import collections
import numpy as np
from capstone import *
from capstone.arm import *
from svcxtract.core import utils
from svcxtract.core import consts
from svcxtract.common import objects as common_objs


class RegisterEvaluator:
    def __init__(self):
        self.start_time = None
        
    def estimate_reg_values_for_trace_object(self, trace_obj, svc_instance): 
        logging.info('Starting register trace.')
        
        logging.debug('Trace object:\n' + json.dumps(trace_obj, indent=4))
        
        self.start_time = timeit.default_timer()
        
        self.svc_analyser = svc_instance
        self.master_trace_obj = trace_obj
        
        # Get all instruction addresses.
        self.all_addresses = list(common_objs.disassembled_firmware.keys())
        self.all_addresses.sort()

        # Keep track of checked traces, to avoid repeating.
        self.checked_traces = []
        self.checked_paths = {}
        self.global_counter = 0
        
        # Keep track of unhandled instructions.
        self.unhandled = []
        
        # Start up instruction queue.
        self.instruction_queue = collections.deque()
            
        # Get starting point for trace from chain.
        start_points = trace_obj.keys()
        # Get the stack pointer value.
        start_stack_pointer = \
            int(common_objs.application_vector_table['initial_sp'])

        for start_point in start_points:
            # Initialise registers at the starting point.
            initialised_regs = {}
            for reg in consts.REGISTERS:
                initialised_regs[reg] = None
            initialised_regs = self.store_register_bytes(
                initialised_regs,
                ARM_REG_PC,
                '{0:08x}'.format(self.get_pc_value(start_point))
            )
            initialised_regs = self.store_register_bytes(
                initialised_regs,
                ARM_REG_SP,
                '{0:08x}'.format(start_stack_pointer)
            )
            
            # Initialise stack/RAM.
            initial_memory = {}
            
            # Keep track of conditional flags.
            condition_flags = self.initialise_condition_flags()
        
            # Keep track of a register (or registers) that are null.
            null_registers = {}
            
            self.checked_paths[hex(start_point)] = {}
            current_path = hex(start_point)
            
            # Add item to queue.
            self.add_to_queue([
                self.trace_register_values,
                start_point,
                initialised_regs,
                initial_memory,
                condition_flags,
                trace_obj[start_point],
                current_path,
                null_registers,
                self.global_counter
            ])
        
        self.queue_handler()
        print('UNHANDLED')
        print(self.unhandled)
        return
    
    # =======================================================================  
    # ------------------------- Trace Path-Related --------------------------
    
    def trace_register_values(self, start_point, register_object,  
                                memory_map, condition_flags, trace_obj, 
                                current_path, null_registers={}, gc=0):
        """"""
        if start_point == None: return None
        # Make sure we aren't branching to the vector table, for some reason.
        code_start_point = common_objs.code_start_address
        # TODO: We just ignore it, for now, but we need to see why it happens.
        if start_point < (code_start_point): 
            logging.error(
                'Branch to AVT!'
            )
            return None
        
        # Get the address of the last instruction in function block,
        #  so that we don't just go on processing the nest function block.
        curr_function_block = utils.id_function_block_for_instruction(
            start_point
        )
        end_of_function_block = utils.id_function_block_end(    
            curr_function_block
        )
        
        # Get branch points/possible end points. 
        (branch_points, end_points, end_point_obj) = \
            self.get_branch_end_points_from_trace_obj(
                trace_obj
            )
        
        logging.debug(  
            'Starting trace at '
            + hex(start_point)
            + ' with block end: '
            + hex(end_of_function_block)
            + ', counter: '
            + str(gc)
            #+ ' and followed path: '
            #+ current_path
        )

        # Start from the starting point within assembly,
        #  and follow the instructions along the chain.
        for ins_address in common_objs.disassembled_firmware:
            if ins_address in common_objs.errored_instructions:
                continue
            # We don't want to process any instruction at an address
            #  lower than start point.
            if ins_address < start_point:
                continue

            # We assume that the code must contain ways to skip inline data
            #  (such as via branches), so if we encounter inline data, 
            #  we must have come to end of executable part of function.
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                return
            
            # If we have arrived at an end point, i.e., an SVC call, then
            #  send the registers and memory map to SVC Analyser, to process.
            if ins_address in end_points:
                svc_name = end_point_obj[ins_address]
                memory_map = {
                    key:memory_map[key] 
                        for key in sorted(memory_map.keys())
                }
                register_object = {
                    key:register_object[key] 
                        for key in sorted(register_object.keys())
                }

                out_obj = {
                    'memory': memory_map,
                    'registers': register_object
                }
                
                logging.debug(
                    'Endpoint reached for '
                    + svc_name
                    + '!\n'
                    + 'memory: '
                    + self.print_memory(memory_map)
                    + '\nregisters: '
                    + self.print_memory(register_object)
                )
                
                # Process the output and get updated memory map.
                memory_map = self.svc_analyser.process_trace_output(
                    {svc_name:out_obj}
                )
                memory_map = {
                    key:memory_map[key] 
                        for key in sorted(memory_map.keys())
                }
                end_points.remove(ins_address)
                
                # Output of SVC Call is an error code stored in register r0.
                #  We assume 0, i.e., no error.
                register_object = self.store_register_bytes(
                    register_object,
                    ARM_REG_R0,
                    '00000000'
                )
                # We've done all the processing we want to, 
                #  for the SVC Call instruction.
                # So continue to next instruction.
                continue

            # Instructions we needn't process (NOP, etc).
            skip_insn = self.check_skip_instruction(ins_address)
            if skip_insn == True:
                continue

            insn = common_objs.disassembled_firmware[ins_address]['insn']
            opcode_id = insn.id
            
            # Debug and trace messages.
            logging.debug('------------------------------------------')
            logging.debug('memory: ' + self.print_memory(memory_map))
            logging.debug('reg: ' + self.print_memory(register_object))
            logging.debug(hex(ins_address) + '  ' + insn.mnemonic + '  ' + insn.op_str)
            
            # Branches require special processing.
            if opcode_id in [ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, 
                    ARM_INS_CBNZ, ARM_INS_CBZ]:
                should_execute_next_instruction = self.process_branch_instruction(
                    register_object,
                    memory_map,
                    trace_obj,
                    current_path,
                    ins_address,
                    condition_flags,
                    branch_points,
                    null_registers
                )
                
                if should_execute_next_instruction == True:
                    continue
                else:
                    return
            # Table Branch instructions require quite a bit of processing.
            elif (opcode_id in [ARM_INS_TBB, ARM_INS_TBH]):
                self.process_table_branch_instruction(
                    register_object,
                    memory_map,
                    condition_flags,
                    trace_obj,
                    current_path,
                    ins_address,
                    null_registers
                )
                return
            # IT instructions.
            elif opcode_id == ARM_INS_IT:
                self.process_it_instruction(
                    register_object,
                    memory_map,
                    trace_obj,
                    current_path,
                    ins_address,
                    condition_flags,
                    null_registers
                )
                return
                
            # Compute the values of the registers.
            (register_object, memory_map, condition_flags, null_registers) = \
                self.process_reg_values_for_instruction(
                    register_object,
                    memory_map,
                    trace_obj,
                    current_path,
                    ins_address,
                    condition_flags,
                    null_registers
                )
            # In the event that PC is passed to POP, there will be a branch.
            #  Presumably we wouldn't continue with the current trace then.
            if register_object == None:
                return
    
    def get_branch_end_points_from_trace_obj(self, trace_obj):
        branch_or_end_points = trace_obj['branch_or_end_points']
        branch_points = list(branch_or_end_points.keys())
        branch_points.sort()
        end_point_obj = {}        
        for address in branch_points:
            if branch_or_end_points[address]['is_end'] == True:
                end_point_obj[address] = \
                    branch_or_end_points[address]['svc_name']
        end_points = list(end_point_obj.keys())
        end_points.sort()
        return (branch_points, end_points, end_point_obj)
        
    def process_branch_instruction(self, register_object, memory_map,
                                    trace_obj, current_path, ins_address,
                                    condition_flags, branch_points, 
                                    null_registers):
        insn = common_objs.disassembled_firmware[ins_address]['insn']
        opcode_id = insn.id
        operands = insn.operands
        next_reg_values = register_object

        should_execute_next_instruction = False
        
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
        elif opcode_id in [ARM_INS_CBZ, ARM_INS_CBNZ]:
            branch_target = operands[1].value.imm
        
        # If branch_target is black-listed, don't proceed.
        if branch_target in common_objs.blacklisted_functions:
            return True
            
        # We process certain functions differently.
        if branch_target in common_objs.memory_access_functions:
            mem_access_function = \
                common_objs.memory_access_functions[branch_target]
            func_type = mem_access_function['type']
            if func_type == consts.MEMSET:
                memory_map = self.process_memset(
                    memory_map,
                    register_object,
                    mem_access_function
                )
            return True
            
        # Check whether we execute the branch, based on conditionals.
        # If it's a conditional branch, then we use previous condition check.
        branch_condition_satisfied = None
        if (((insn.cc != ARM_CC_AL) and (insn.cc != ARM_CC_INVALID)) 
                or (opcode_id in [ARM_INS_CBZ, ARM_INS_CBNZ])):
            branch_condition_satisfied = self.check_branch_condition_satisfied(
                opcode_id,
                insn,
                condition_flags,
                next_reg_values
            )
            if branch_condition_satisfied == False:
                should_execute_next_instruction = True
                branch_target = None
            # If the outcome is None, then execute both paths.
            elif branch_condition_satisfied == None:
                should_execute_next_instruction = True
            
        should_branch = False
        if branch_condition_satisfied != False:
            # Check trace path-related conditions for branching.
            (should_branch, new_path) = self.check_should_branch(
                current_path,
                trace_obj,
                ins_address,
                branch_target
            )
        
        # Check for conditions where we would want to execute next instruction
        #  in the event we are NOT branching.
        if (should_branch == False):
            should_execute_next_instruction = True
            return should_execute_next_instruction
            
        # From this point on within this function, all code relates to the 
        #  branch.
        
        # Set current path to the path returned by the branch check.
        current_path = new_path
        
        # Set trace object to next level down.
        # This is only relevant if opcodes are B, BL (because we used those
        #  in making the chain).
        # Also, this is not relevant for self-loops.
        if opcode_id in [ARM_INS_B, ARM_INS_BL]:
            if ins_address in trace_obj['branch_or_end_points']:
                new_trace_obj = trace_obj['branch_or_end_points'][ins_address]
                trace_obj = new_trace_obj['branch_target'][branch_target]
        
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
        
        # If BX, we may need to get previous level of trace obj.
        if opcode_id == ARM_INS_BX:
            trace_obj = self.get_return_trace_obj(
                trace_obj,
                branch_target
            )
        logging.debug('Counter: ' + str(self.global_counter))
        
        # Branch.
        self.add_to_queue([
            self.trace_register_values,
            branch_target,
            copy.deepcopy(register_object),
            copy.deepcopy(memory_map),
            copy.deepcopy(condition_flags),
            copy.deepcopy(trace_obj),
            current_path,
            copy.deepcopy(null_registers),
            self.global_counter
        ])
        
        # Increment counter to keep track of branches.
        self.global_counter+=1
        
        return should_execute_next_instruction

    def check_should_branch(self, current_path, trace_obj, calling_address, 
                                branch_target):
        # The target might have been set to null on purpose, 
        #  to prevent the branch.
        if (branch_target == None): 
            return (False, None)

        if calling_address in common_objs.errored_instructions:
            return (False, None)
            
        if branch_target < common_objs.code_start_address:
            return (False, None)
            
        logging.debug('Checking whether we should follow this branch')

        insn = common_objs.disassembled_firmware[calling_address]['insn']
        opcode_id = insn.id
        
        # ----------- Do basic checks first --------------
        
        # If null target not in f/w addresses, we can't proceed with branch.
        if (branch_target not in self.all_addresses):
            logging.warning(
                'Branch target '
                + hex(branch_target)
                + ' does not exist in firmware. '
                + hex(calling_address)
            )
            return (False, None)
            
        # If target is actually data, there it can't be executed.
        if common_objs.disassembled_firmware[branch_target]['is_data']==True:
            logging.warning(
                'Branch target has been marked as data.'
            )
            return (False, None)

        # If current and target are equal, then it's a perpetual self-loop.
        if calling_address == branch_target:
            return (False, None)

        # Get function blocks.
        curr_function_block = utils.id_function_block_for_instruction(
            calling_address
        )
        logging.debug('Current function block: ' + hex(curr_function_block))
        target_function_block = utils.id_function_block_for_instruction(
            branch_target
        )
        logging.debug('Target function block: ' + hex(target_function_block))
        # If the target contains a perpetual self-loop, 
        #  it will have been blacklisted.
        if target_function_block in common_objs.blacklisted_functions:
            logging.debug('Target function block has been blacklisted.')
            return (False, None)
        
        # The Reset Handler has a lot of self-looping. Avoid.
        reset_handler = int(common_objs.application_vector_table['reset'])
        if curr_function_block == reset_handler:
            if curr_function_block == target_function_block:
                logging.debug('Avoiding internal loops within Reset Handler.')
                return (False, None)
            # We also want to avoid bl to anything other than what is in 
            #  trace object, IF the caller is the reset handler.
            elif calling_address not in trace_obj['branch_or_end_points']:
                logging.debug('Avoiding external branches from Reset Handler.')
                return (False, None)
            
        # Check if path already traced.
        (already_traced, new_path) = self.check_already_traced(
            current_path,
            calling_address,
            branch_target
        )
        if already_traced == True:
            logging.debug('Exact path already traced. Skipping.')
            return (False, None)
            
        # If it's BX LR, then it would just be returning.
        # Do we really want to add to the trace path for this?
        # If we don't, we could move this check up a bit.
        if opcode_id == ARM_INS_BX:
            return (True, new_path)
            
        
        # ------------ Slightly more complex checks -------------

        if (curr_function_block != target_function_block):
            if calling_address not in trace_obj['branch_or_end_points']:
                logging.debug(
                    'Branch point is not present in trace object.'
                )
                function_block = \
                    common_objs.function_blocks[target_function_block]
                call_depth = function_block['call_depth']
                logging.debug('Call depth of target is ' + str(call_depth))
                function_block = None
                # We don't want to waste time on functions that have very 
                #  high call-depth.
                if call_depth > common_objs.max_call_depth:
                    logging.debug('Call-depth is too high.')
                    return (False, None)

        logging.debug(
            'Path not previously taken. Continuing with counter: '  
            + str(self.global_counter)
        )
        return (True, new_path)

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
            elif ((flags['c'] == 0) and (flags['z'] == 1)):
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
            elif ((flags['z'] == 1) and (flags['n'] != flags['v'])):
                is_condition_satisfied = True
            else:
                is_condition_satisfied = False 
        return is_condition_satisfied
    
    def update_condition_flags(self, condition_flags, result, carry=None, overflow=None):
        if carry != None:
            condition_flags['c'] = carry
        if overflow != None:
            condition_flags['v'] = overflow
        result_in_bits = self.get_binary_representation(result, 32)
        if result_in_bits[0] == '0':
            condition_flags['n'] = 0
        else:
            condition_flags['n'] = 1
        if '1' in result_in_bits:
            condition_flags['z'] = 0
        else:
            condition_flags['z'] = 1
        return condition_flags
            
    def check_skip_instruction(self, address):
        address_object = common_objs.disassembled_firmware[address]
        if address_object['is_data'] == True:
            return True
        if address_object['insn'].id == ARM_INS_NOP:
            return True
        if address_object['insn'].id in [ARM_INS_MOV, ARM_INS_MOVW]:
            operands = address_object['insn'].operands
            op1 = operands[0].value.reg
            op2 = operands[1].value.reg
            if op1 == op2:
                return True
        return False
    
    def check_already_traced(self, current_path, calling_address, branch_target):
        # Create new path string.
        calling_address = hex(calling_address)
        branch_target = hex(branch_target)
        branch_path = calling_address + ',' + branch_target
        new_path = current_path + ',' + branch_path
        
        # Check whether this path has been traced before.
        path_list = new_path.split(',')
        traced_paths = self.checked_paths
        counter = 0
        previously_traced = True
        while len(path_list) > 0:
            element = path_list[0]
            if element not in traced_paths.keys():
                previously_traced = False
                if len(path_list) == 2:
                    traced_paths[path_list[0]] = {
                        path_list[1]: {}
                    }
                elif len(path_list) == 1:
                    traced_paths[path_list[0]] = {}
                    if element != branch_target:
                        logging.critical('Invalid trace path!')
                        return (True, None)
                else:
                    logging.critical('Invalid trace path!')
                    return (True, None)
            path_list = path_list[1:]
            traced_paths = traced_paths[element]
            counter += 1
            
        # Do not modify the order of this and subsequent return.
        if common_objs.allow_loops == True:
            return (False, new_path)
            
        if previously_traced == True:
            return (True, None)
            
        # Check for loops.
        # Loops may be of different lengths and between different functions,
        #  i.e., addressA in funcX calls addressB in funcY, then 
        #  addressC in funcY calls addressD in funcX, and they continue.
        split_path = current_path.split(',')
        split_path.append(calling_address)
        split_path.append(branch_target)
        for i in range(2,16):
            if len(split_path) < (2*i):
                break
            path_end = split_path[(-1*i):]
            path_end_str = path_end[0]
            for x in range(1,(len(path_end)-1)):
                path_end_str += (',' + path_end[x])
            remaining_path = split_path[0:(-1*i)]
            remaining_path_str = remaining_path[0]
            for y in range(1,(len(remaining_path)-1)):
                remaining_path_str += (',' + remaining_path[y])
            if remaining_path_str.endswith(path_end_str):
                logging.debug('Path is looping. Breaking out.')
                return (True, None)
        return (False, new_path)
        
    def check_neighbour_ins(self, start_address, end_address, ins_list):
        address = start_address
        is_required_insn = False
        while address <= end_address:
            if address not in common_objs.disassembled_firmware:
                address = self.get_next_address(self.all_addresses, address)
                continue
            if (common_objs.disassembled_firmware[address]['is_data'] == True):
                address = self.get_next_address(self.all_addresses, address)
                continue
            opcode_id = common_objs.disassembled_firmware[address]['insn'].id
            if opcode_id in ins_list:
                is_required_insn = True
            address = self.get_next_address(self.all_addresses, address)
        return is_required_insn
        
    #----------------  Table Branch-related ----------------
    def process_table_branch_instruction(self, register_object, memory_map,
                                            condition_flags, trace_obj, 
                                            current_path, ins_address, 
                                            null_registers):
        # The Definitive Guide to the ARM Cortex-M3
        #  By Joseph Yiu (pg 76)
        
        insn = common_objs.disassembled_firmware[ins_address]['insn']
        opcode_id = insn.id
        operands = insn.operands
        next_reg_values = register_object
        
        # We always use (current address + 4) to identify next block.
        pc_address = ins_address + 4
        
        # Get the indexing register, the value it is compared to, and the 
        #  address at which the comparison takes place.
        (comp_register, comp_value, comp_address) = \
            self.get_table_branch_register_comparison_value(
                next_reg_values,
                ins_address,
                condition_flags
            )

        # Get all possible branch addresses.
        table_branch_addresses = self.get_table_branch_addresses(
            ins_address,
            opcode_id,
            comp_value
        )
                
        # Get address to skip to, i.e., if index is greater than comp_value.
        # This will be present in a preceding branch instruction.
        skip_address = self.get_table_skip_condition(
            comp_address,
            ins_address,
            next_reg_values
        )
            
        # Get the actual value of indexing register.
        actual_value = self.get_register_bytes(
            next_reg_values,
            comp_register,
            'int'
        )

        branch_address = table_branch_addresses[actual_value]
        if branch_address not in common_objs.disassembled_firmware:
            logging.critical(
                'Unable to index into table. '
                + 'Address: '
                + hex(branch_address)
            )
            return # TODO: Handle this case.
        debug_msg = (
            'Table branch to ' 
            + hex(branch_address)
        )
         
        # Branch, either to address indicated by table, or to 
        #  the skip address.
        (should_branch, new_path) = self.check_should_branch(
            current_path,
            trace_obj,
            ins_address,
            branch_address
        )
        if should_branch != True:
            branch_address = skip_address
            
        debug_msg += (' with counter: ' + str(self.global_counter))
        logging.debug(debug_msg)
        
        self.add_to_queue([
            self.trace_register_values,
            branch_address,
            copy.deepcopy(next_reg_values),
            copy.deepcopy(memory_map),
            copy.deepcopy(condition_flags),
            copy.deepcopy(trace_obj),
            new_path,
            copy.deepcopy(null_registers),
            self.global_counter
        ])
        self.global_counter+=1     
            
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
            value = self.get_firmware_bytes(
                index_address, 
                num_bytes=mul_factor
            )
            value = int(value, 16)
            branch_address = pc_address + (2*value)
            table_branch_addresses.append(branch_address)
        
        return table_branch_addresses
    
    def get_table_branch_register_comparison_value(self, register_object, 
                ins_address, condition_flags):
        insn = common_objs.disassembled_firmware[ins_address]['insn']
        opcode_id = insn.id
        operands = insn.operands
        next_reg_values = register_object

        index_register = operands[0].value.mem.index
        
        address = ins_address
        
        comparison_value = None
        comp_address = None
        for i in range(5):
            address = self.get_previous_address(self.all_addresses, address)
            prev_insn = common_objs.disassembled_firmware[address]
            if prev_insn['is_data'] == True:
                continue
            if prev_insn['insn'].id != ARM_INS_CMP:
                continue
            if prev_insn['insn'].operands[0].value.reg != index_register:
                continue
            comp_address = address
            (comparison_value, _) = self.get_src_reg_value(
                next_reg_values,
                prev_insn['insn'].operands[1], 
                'int'
            )
            logging.debug(
                'Register '
                + str(index_register)
                + ' has been compared with value '
                + str(comparison_value)
            )
            break
        return (index_register, comparison_value, comp_address)
            
    def get_table_skip_condition(self, start_address, end_address, next_reg_values):
        condition = None
        branch_target = None
        
        address = start_address
        while address < end_address:
            address = self.get_next_address(self.all_addresses, address)
            add_ins = common_objs.disassembled_firmware[address]
            if add_ins['is_data'] == True:
                continue
            insn = add_ins['insn']
            opcode_id = insn.id
            operands = insn.operands
            if opcode_id not in [ARM_INS_B, ARM_INS_BL, ARM_INS_BLX,
                    ARM_INS_BX, ARM_INS_CBNZ, ARM_INS_CBZ]:
                continue
            condition = insn.cc
            if opcode_id in [ARM_INS_B, ARM_INS_BL]:
                branch_target = operands[0].value.imm
            elif opcode_id in [ARM_INS_BX, ARM_INS_BLX]:
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
                                trace_obj, current_path, ins_address, 
                                condition_flags, null_registers):
        insn = common_objs.disassembled_firmware[ins_address]['insn']
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
            self.execute_it_conditionals(
                copy.deepcopy(register_object),
                copy.deepcopy(memory_map),
                copy.deepcopy(condition_flags),
                copy.deepcopy(trace_obj),
                current_path,
                then_instructions,
                ins_address,
                postconditional_ins_address,
                copy.deepcopy(null_registers)
            )
        
        # Execute Else instructions.
        if execute_else_instructions == True:
            self.execute_it_conditionals(
                copy.deepcopy(register_object),
                copy.deepcopy(memory_map),
                copy.deepcopy(condition_flags),
                copy.deepcopy(trace_obj),
                current_path,
                else_instructions,
                ins_address,
                postconditional_ins_address,
                copy.deepcopy(null_registers)
            )
        
    def execute_it_conditionals(self, register_object, memory_map, condition_flags,
                                    trace_obj, current_path, ins_list, 
                                    original_address, branching_address,
                                    null_registers):
        next_reg_values = register_object
            
        for conditional_address in ins_list:
            insn = common_objs.disassembled_firmware[conditional_address]['insn']
            logging.debug('------------------------------------------')
            logging.debug('memory: ' + self.print_memory(memory_map))
            logging.debug('reg: ' + self.print_memory(next_reg_values))
            logging.debug(
                hex(conditional_address) 
                + '  ' + insn.mnemonic 
                + '  ' + insn.op_str
            )
            opcode_id = insn.id
            if opcode_id in [ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, 
                                ARM_INS_CBNZ, ARM_INS_CBZ]:
                # Get branch points/possible end points. 
                (branch_points, end_points, end_point_obj) = \
                    self.get_branch_end_points_from_trace_obj(
                        trace_obj
                    )
            
                # The output of process_branch_instruction is a boolean,
                #  indicating whether we should execute the next instruction.
                _ = self.process_branch_instruction(
                    next_reg_values,
                    memory_map,
                    trace_obj,
                    current_path,
                    conditional_address,
                    condition_flags,
                    branch_points,
                    null_registers
                )
            else:
                (next_reg_values, memory_map, condition_flags, null_registers) = \
                    self.process_reg_values_for_instruction(
                        next_reg_values,
                        memory_map,
                        trace_obj,
                        current_path,
                        conditional_address,
                        condition_flags,
                        null_registers
                    )
                
            # In the event that PC is passed to POP, there will be a branch.
            #  Presumably we wouldn't continue with the current trace then.
            if next_reg_values == None:
                return
        
        if len(ins_list) > 0:
            start_branch = ins_list[-1]
        else:
            start_branch = original_address
            
        # Branch from postconditional.
        self.add_to_queue([
            self.trace_register_values,
            branching_address,
            copy.deepcopy(next_reg_values),
            copy.deepcopy(memory_map),
            copy.deepcopy(condition_flags),
            copy.deepcopy(trace_obj),
            current_path,
            copy.deepcopy(null_registers),
            self.global_counter
        ])
        self.global_counter += 1
        
    # =======================================================================  
    # ----------------------- Instruction Processing ------------------------
    
    def process_reg_values_for_instruction(self, register_object, memory_map, 
                                trace_obj, current_path, ins_address, 
                                condition_flags, null_registers):
        instruction = common_objs.disassembled_firmware[ins_address]['insn']
        
        # If the instruction is to be executed conditionally, first check 
        #  if the condition is satisfied.
        if condition_flags != None:
            if ((instruction.cc != ARM_CC_AL) and (instruction.cc != ARM_CC_INVALID)): 
                is_condition_satisfied = self.check_condition_satisfied(
                    instruction.cc,
                    condition_flags
                )
                if is_condition_satisfied == False:
                    return (register_object, memory_map, condition_flags, null_registers)
        
        # Process instruction.        
        if instruction.id == ARM_INS_ADC:
            (register_object, condition_flags, null_registers) = self.process_adc(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id in [ARM_INS_ADD, ARM_INS_ADDW]:
            (register_object, condition_flags, null_registers) = self.process_add(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_ADR:
            (register_object, null_registers) = self.process_adr(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_AND:
            (register_object, condition_flags, null_registers) = self.process_and(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_ASR:
            (register_object, condition_flags, null_registers) = self.process_asr(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_BFC:
            (register_object, null_registers) = self.process_bfc(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_BFI:
            (register_object, null_registers) = self.process_bfi(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_BIC:
            (register_object, condition_flags, null_registers) = self.process_bic(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_CLZ:
            (register_object, null_registers) = self.process_clz(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id in [ARM_INS_CMN, ARM_INS_CMP, ARM_INS_TEQ, ARM_INS_TST]:
            (condition_flags, null_registers) = self.process_condition(
                ins_address,
                register_object,
                condition_flags,
                null_registers
            )
            if condition_flags == None:
                register_object = None
        elif instruction.id == ARM_INS_EOR:
            (register_object, condition_flags, null_registers) = self.process_eor(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_LDM:
            (register_object, memory_map, null_registers) = self.process_ldm(
                ins_address,
                instruction,
                register_object,
                memory_map,
                trace_obj,
                current_path,
                condition_flags,
                null_registers
            ) 
        elif instruction.id in [ARM_INS_LDR, ARM_INS_LDREX, 
                    ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH, 
                    ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB]:
            (register_object, memory_map, null_registers) = self.process_ldr(
                ins_address,
                instruction,
                register_object,
                memory_map,
                trace_obj,
                current_path,
                condition_flags,
                null_registers
            ) 
        elif instruction.id == ARM_INS_LDRD:
            (register_object, memory_map, null_registers) = self.process_ldrd(
                ins_address,
                instruction,
                register_object,
                memory_map,
                trace_obj,
                current_path,
                condition_flags,
                null_registers
            ) 
        elif instruction.id == ARM_INS_LSL:
            (register_object, condition_flags, null_registers) = self.process_lsl(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_LSR:
            (register_object, condition_flags, null_registers) = self.process_lsr(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id in [ARM_INS_MOV, ARM_INS_MOVW]:
            (register_object, condition_flags, null_registers) = self.process_mov(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_MUL:
            (register_object, condition_flags, null_registers) = self.process_mul(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_MVN:
            (register_object, condition_flags, null_registers) = self.process_mvn(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_ORN:
            (register_object, condition_flags, null_registers) = self.process_orn(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_ORR:
            (register_object, condition_flags, null_registers) = self.process_orr(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_POP:
            (register_object, memory_map, null_registers) = self.process_pop(
                register_object,
                trace_obj,
                ins_address,
                instruction,
                memory_map,
                current_path,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_PUSH:
            (register_object, memory_map, null_registers) = self.process_push(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_REV:
            (register_object, null_registers) = self.process_rev(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_ROR:
            (register_object, condition_flags, null_registers) = self.process_ror(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_RRX:
            (register_object, condition_flags, null_registers) = self.process_rrx(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_RSB:
            (register_object, condition_flags, null_registers) = self.process_rsb(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_SBC:
            (register_object, condition_flags, null_registers) = self.process_sbc(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id in [ARM_INS_STR, ARM_INS_STREX, 
                ARM_INS_STRH, ARM_INS_STREXH, 
                ARM_INS_STRB, ARM_INS_STREXB]:
            (register_object, memory_map, null_registers) = self.process_str(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_STRD:
            (register_object, memory_map, null_registers) = self.process_strd(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_STM:
            (register_object, memory_map, null_registers) = self.process_stm(
                ins_address,
                instruction,
                register_object,
                memory_map,
                condition_flags,
                null_registers
            )
        elif instruction.id in [ARM_INS_SUB, ARM_INS_SUBW]:
            (register_object, condition_flags, null_registers) = self.process_sub(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id in [ARM_INS_SXTB, ARM_INS_SXTH]:
            (register_object, null_registers) = self.process_sxt(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id in [ARM_INS_UXTB, ARM_INS_UXTH]:
            (register_object, null_registers) = self.process_uxt(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
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
                if instruction.mnemonic not in self.unhandled:
                    self.unhandled.append(instruction.mnemonic)
            return (register_object, memory_map, condition_flags, null_registers)
        return (register_object, memory_map, condition_flags, null_registers)

    def update_null_registers(self, null_registers, src_ops, dst_ops):
        for dst_op in dst_ops:
            if dst_op in src_ops:
                continue
            if dst_op == ARM_REG_INVALID:
                continue
            if dst_op in list(null_registers.keys()):
                del null_registers[dst_op]
    
        for src_op in src_ops:
            if src_op == ARM_REG_INVALID:
                continue
            if src_op in list(null_registers.keys()):
                for dst_op in dst_ops:
                    logging.debug(
                        'Register '
                        + str(dst_op)
                        + ' tainted by null register '
                        + str(src_op)
                    )
                    null_registers[dst_op] = {}
                break
        return null_registers
    
    def process_adc(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        
        # Get values.
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            return (next_reg_values, condition_flags, null_registers)

        carry_in = condition_flags['c']
        if carry_in == None: carry_in = 0
        (result, carry, overflow) = self.add_with_carry(
            start_value,
            add_value,
            carry_in
        )

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_add(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]
            
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        
        # Get values.
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values,
            add_operand,
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        (result, carry, overflow) = self.add_with_carry(start_value, add_value)

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags, null_registers)
    
    def process_adr(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        pc_value = self.get_mem_access_pc_value(ins_address)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )        
        if add_value == None: 
            return (next_reg_values, null_registers)
        
        if operands[1].subtracted == True:
            result = pc_value - add_value
        else:
            result = pc_value + add_value

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        return (next_reg_values, null_registers)
        
    def process_and(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            and_operand = operands[1]
        else:
            start_operand = operands[1]
            and_operand = operands[2]
            
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, and_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (and_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            and_operand, 
            'int',
            condition_flags['c']
        )
        if and_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        np_dtype = self.get_numpy_type([start_value, and_value])
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
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_asr(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )
        if src_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Process shift.
        if len(operands) == 2:
            shift_value = self.get_shift_value(next_reg_values, operands[1])
            (result, carry) = self.arithmetic_shift_right(src_value, shift_value)
        else:
            shift_value = self.get_shift_value(next_reg_values, operands[2])
            (result, carry) = self.arithmetic_shift_right(src_value, shift_value)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_bfc(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)

        # We needn't update null registers, because src and dst are the same.
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            operands[0], 
            'int'
        )
        if src_value == None: 
            return (next_reg_values, null_registers)
        
        (lsb, _) = self.get_src_reg_value(next_reg_values, operands[1], 'int')
        (width, _) = self.get_src_reg_value(next_reg_values, operands[2], 'int')
        bit_length = self.get_bit_length(src_value)
        bits = self.get_binary_representation(src_value, bit_length)
        end_idx = bit_length - lsb -1
        start_idx = bit_length - lsb - width
        
        new_bits = ''
        for i in range(bit_length):
            if i in range(start_idx, (end_idx+1)):
                new_bits += '0'
            else:
                new_bits += bits[i]

        new_value = self.convert_bits_to_type(new_bits, type(src_value))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            new_value
        )
        return (next_reg_values, null_registers)
    
    def process_bfi(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [dst_operand, operands[1].value.reg],
            [dst_operand]
        )
        
        (original_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[0],
            'int'
        )
        if original_value == None: 
            return (next_reg_values, null_registers)
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[1],
            'int'
        )
        if src_value == None: 
            return (next_reg_values, null_registers)
        
        (lsb, _) = self.get_src_reg_value(next_reg_values, operands[2], 'int')
        (width, _) = self.get_src_reg_value(next_reg_values, operands[3], 'int')
        bit_length = self.get_bit_length(src_value)
        original_bits = self.get_binary_representation(original_value, bit_length)
        src_bits = self.get_binary_representation(src_value, bit_length)
        
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

        new_value = self.convert_bits_to_type(new_bits, type(original_value))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            new_value
        )
        return (next_reg_values, null_registers)
        
    def process_bic(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            not_operand = operands[1]
        else:
            start_operand = operands[1]
            not_operand = operands[2]
            
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, not_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (not_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            not_operand, 
            'int',
            condition_flags['c']
        )
        if not_value == None: 
            return (next_reg_values, condition_flags, null_registers)

        np_dtype = self.get_numpy_type([start_value, not_value])
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
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
    
    def process_clz(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        src_operand = operands[1]
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [src_operand.value.reg],
            [dst_operand]
        )
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None: 
            return (next_reg_values, null_registers)
        
        num_bits = int(len(src_value) * 2)
        result_in_bits = self.get_binary_representation(src_value, num_bits)
        
        num_leading_zeros = 0
        for i in range(num_bits):
            if result_in_bits[i] == '0':
                num_leading_zeros += 1
            else:
                break
        result = self.convert_type(num_leading_zeros, 'hex')
        result = result.zfill(8)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        return (next_reg_values, null_registers)
        
    def process_condition(self, ins_address, register_object, condition_flags,
                            null_registers):
        instruction = common_objs.disassembled_firmware[ins_address]['insn']
        opcode_id = instruction.id
        operands = instruction.operands
        
        (operand1, _) = self.get_src_reg_value(
            register_object, 
            operands[0], 
            'int'
        )
        if operand1 == None: 
            condition_flags = self.initialise_condition_flags()
            return (condition_flags, null_registers)
        (operand2, carry) = self.get_src_reg_value(
            register_object, 
            operands[1], 
            'int',
            condition_flags['c']
        )
        if operand2 == None: 
            condition_flags = self.initialise_condition_flags()
            return (condition_flags, null_registers)
        
        # Process null_registers
        if (operands[0].value.reg) in null_registers:
            condition_flags = self.initialise_condition_flags()
            return (condition_flags, null_registers)
        if operands[1].type == ARM_OP_REG:
            if (operands[0].value.reg) in null_registers:
                condition_flags = self.initialise_condition_flags()
                return (condition_flags, null_registers)
        
        # Test conditional.
        overflow = None
        if opcode_id == ARM_INS_CMN:
            (result, carry, overflow) = \
                self.add_with_carry(operand1, operand2)
        elif opcode_id == ARM_INS_CMP:
            (result, carry, overflow) = \
                self.add_with_carry(operand1, operand2, 1, sub=True)
        elif opcode_id == ARM_INS_TST:
            np_dtype = self.get_numpy_type([operand1, operand2])
            result = np.bitwise_and(
                operand1.astype(np_dtype),
                operand2.astype(np_dtype),
                dtype=np_dtype,
                casting='safe'
            )
        elif opcode_id == ARM_INS_TEQ:
            np_dtype = self.get_numpy_type([operand1, operand2])
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
        return (condition_flags, null_registers)
        
    def process_eor(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            orr_operand = operands[1]
        else:
            start_operand = operands[1]
            orr_operand = operands[2]
            
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, orr_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        np_dtype = self.get_numpy_type([start_value, orr_value])
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
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_null_registers_ldr(self, null_registers, dst_operand, null_value,
                                        address):
        if dst_operand in null_registers:
            del null_registers[dst_operand]
        if null_value == True:
            address_type = self.get_address_type(address)
            if ((address_type != consts.ADDRESS_FIRMWARE) 
                    and (address_type != consts.ADDRESS_RAM)):
                logging.debug(
                    'LDR source is unavailable. Register '
                    + str(dst_operand)
                    + ' marked as null.'
                )
                null_registers[dst_operand] = {}
        return null_registers
                
    def process_ldm(self, ins_address, instruction, current_reg_values, 
                        memory_map, trace_obj, current_path, condition_flags,
                        null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        src_register = operands[0]
        (address, _) = self.get_src_reg_value(next_reg_values, src_register, 'int')
        if address == None: 
            return (next_reg_values, memory_map, null_registers)
        
        for operand in operands[1:]:
            dst_operand = self.get_dst_operand(operand)
            if dst_operand == None: 
                return (next_reg_values, memory_map, null_registers)
            (reg_value, null_value) = self.get_value_from_memory(
                memory_map,
                address
            )
            
            null_registers = self.process_null_registers_ldr(
                null_registers,
                dst_operand,
                null_value,
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
                pc_target = [dst_operand]
                logging.debug('PC branch to ' + str(pc_target))
                (should_branch, new_path) = self.check_should_branch(
                    current_path,
                    trace_obj,
                    ins_address,
                    pc_target
                )
                
                trace_obj = self.get_return_trace_obj(
                    trace_obj,
                    pc_target
                )
                
                if should_branch == True:
                    self.add_to_queue([
                        self.trace_register_values,
                        pc_target,
                        copy.deepcopy(next_reg_values),
                        copy.deepcopy(memory_map),
                        copy.deepcopy(condition_flags),
                        copy.deepcopy(trace_obj),
                        new_path,
                        copy.deepcopy(null_registers),
                        self.global_counter
                    ])
                    self.global_counter+=1
                    return(None, None, None)
                else:
                    return (next_reg_values, memory_map, null_registers)
                
        # Update base register if needed.
        if instruction.writeback:
            next_reg_values = self.store_register_bytes(
                next_reg_values,
                src_register.value.reg,
                address
            )
        return (next_reg_values, memory_map, null_registers)
        
    def process_ldr(self, ins_address, instruction, current_reg_values, 
                        memory_map, trace_obj, current_path, condition_flags,
                        null_registers):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, memory_map, null_registers)
        
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
            return (next_reg_values, memory_map, null_registers)

        # If dst_operand is PC, then it causes branch.
        if dst_operand == ARM_REG_PC:
            pc_target = self.get_register_bytes(next_reg_values, dst_operand, 'int')
            logging.debug('PC branch to ' + str(pc_target))
            (should_branch, new_path) = self.check_should_branch(
                current_path,
                trace_obj,
                ins_address,
                pc_target
            )
            
            trace_obj = self.get_return_trace_obj(
                trace_obj,
                pc_target
            )
            
            if should_branch == True:
                self.add_to_queue([
                    self.trace_register_values,
                    pc_target,
                    copy.deepcopy(next_reg_values),
                    copy.deepcopy(memory_map),
                    copy.deepcopy(condition_flags),
                    copy.deepcopy(trace_obj),
                    new_path,
                    copy.deepcopy(null_registers),
                    self.global_counter
                ])
                self.global_counter+=1
                return(None, None, null_registers)
            else:
                return (next_reg_values, memory_map, null_registers)
            
        logging.debug(
            'LDR address: ' + hex(src_memory_address)
        )
        
        num_bytes = 4
        if opcode_id in [ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDREXB]:
            num_bytes = 1
        elif opcode_id in [ARM_INS_LDRH, ARM_INS_LDRSH, ARM_INS_LDREXH]:
            num_bytes = 2
        if src_memory_address % num_bytes != 0:
            logging.warning('Misaligned LDR/H/B')
        num_halfbytes = int(num_bytes*2)
        
        (src_value, null_value) = self.get_value_from_memory(
            memory_map,
            src_memory_address,
            unprocessed=True
        )

        # Hacky method to ensure both branches are
        #  taken if an LDR value is used for comparison, 
        #  and the value does not actually exist.
        # We only do this if the address is outside the memory map
        #  range. If the address is within the memory map or firmware range,
        #  we just use all 0's only.
        null_registers = self.process_null_registers_ldr(
            null_registers,
            dst_operand,
            null_value,
            src_memory_address
        )
         
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
            return (next_reg_values, memory_map, null_registers)
                    
        # Get the required bytes.
        src_value = src_value.zfill(8)
        
        src_value = src_value[(-1*num_halfbytes):]

        if ((opcode_id == ARM_INS_LDRB) 
                or (opcode_id == ARM_INS_LDRH)
                or (opcode_id == ARM_INS_LDREXB) 
                or (opcode_id == ARM_INS_LDREXH)):
            src_value = src_value.zfill(8)
        elif ((opcode_id == ARM_INS_LDRSB) or (opcode_id == ARM_INS_LDRSH)):
            src_value = self.sign_extend(src_value)
        
        logging.trace('Value to load: ' + str(src_value))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            src_value
        )
        return (next_reg_values, memory_map, null_registers)
    
    def process_ldrd(self, ins_address, instruction, current_reg_values, 
                        memory_map, trace_obj, current_path, condition_flags,
                        null_registers):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        dst_operand1 = self.get_dst_operand(operands[0])
        if dst_operand1 == None: 
            return (next_reg_values, memory_map, null_registers)
        dst_operand2 = self.get_dst_operand(operands[1])
        if dst_operand2 == None: 
            return (next_reg_values, memory_map, null_registers)
        
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
            return (next_reg_values, memory_map, null_registers)
            
        #Operand1.
        logging.debug(
            'LDR address: ' + hex(src_memory_address)
        )        
        (src_value1, null_value) = self.get_value_from_memory(
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
            
        null_registers = self.process_null_registers_ldr(
            null_registers,
            dst_operand1,
            null_value,
            src_memory_address
        )
            
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
        (src_value2, _) = self.get_value_from_memory(
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
        
        null_registers = self.process_null_registers_ldr(
            null_registers,
            dst_operand2,
            null_value,
            src_memory_address+4
        )
        
        logging.trace('Value to load: ' + str(src_value2))
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand2,
            src_value2
        )
        return (next_reg_values, memory_map, null_registers)
        
    def process_lsl(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (src_value, carry) = self.get_src_reg_value(next_reg_values, operands[1], 'int')
        if src_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        # Process shift.
        if len(operands) == 2:
            result = src_value
        else:
            shift_value = self.get_shift_value(next_reg_values, operands[2])
            (result, carry) = self.logical_shift_left(src_value, shift_value)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_lsr(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )
        if src_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Process shift.
        if len(operands) == 2:
            shift_value = self.get_shift_value(next_reg_values, operands[1])
            (result, carry) = self.logical_shift_right(src_value, shift_value)
        else:
            shift_value = self.get_shift_value(next_reg_values, operands[2])
            (result, carry) = self.logical_shift_right(src_value, shift_value)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_mov(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        if len(operands) != 2:
            logging.error('More than 2 ops ' + instruction.op_str)
            sys.exit(0)
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (result, carry) = self.get_src_reg_value(next_reg_values, operands[1])
        if operands[1].type == ARM_OP_REG: carry = None
        if result == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
    
    def process_mul(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            operand1 = operands[0]
            operand2 = operands[1]
        else:
            operand1 = operands[1]
            operand2 = operands[2]
           
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operand1.value.reg, operand2.value.reg],
            [dst_operand]
        )
        
        (value1, _) = self.get_src_reg_value(next_reg_values, operand1, 'int')
        if value1 == None: 
            return (next_reg_values, condition_flags, null_registers)
        (value2, _) = self.get_src_reg_value(next_reg_values, operand2, 'int')
        if value2 == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        mul_value = value1 * value2
        mul_value = '{0:08x}'.format(mul_value)
        mul_value = mul_value.zfill(8)
        result = mul_value[-8:]

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result
            )
        return (next_reg_values, condition_flags, null_registers)
    
    def process_mvn(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        if len(operands) != 2:
            logging.error('More than 2 ops ' + instruction.op_str)
            sys.exit(0)
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int',
            condition_flags['c']
        )
        if src_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        np_dtype = self.get_numpy_type([src_value])
        result = np.bitwise_not(
            src_value.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_orn(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            orr_operand = operands[1]
        else:
            start_operand = operands[1]
            orr_operand = operands[2]
            
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, orr_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        np_dtype = self.get_numpy_type([start_value, orr_value])
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
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_orr(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            orr_operand = operands[1]
        else:
            start_operand = operands[1]
            orr_operand = operands[2]
            
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, orr_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        np_dtype = self.get_numpy_type([start_value, orr_value])
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
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_pop(self, current_reg_values, trace_obj, ins_address,
                        instruction, memory_map, current_path, 
                        condition_flags, null_registers):
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
            logging.debug('Returning to ' + str(pc_target) + ' (POP PC)')
            # Since POP is essentially returning, we needn't do a branch check?
            # We need to get a revised trace_obj.
            trace_obj = self.get_return_trace_obj(
                trace_obj,
                pc_target
            )
            self.add_to_queue([
                self.trace_register_values,
                pc_target,
                copy.deepcopy(next_reg_values),
                copy.deepcopy(memory_map),
                copy.deepcopy(condition_flags),
                copy.deepcopy(trace_obj),
                current_path,
                copy.deepcopy(null_registers),
                self.global_counter
            ])
            self.global_counter+=1
            return (None, memory_map, null_registers)
        return (next_reg_values, memory_map, null_registers)
    
    def process_push(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags, null_registers):
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

        return (next_reg_values, memory_map, null_registers)
        
    def process_rev(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[1])
        if src_value == None: 
            return (next_reg_values, null_registers)
        
        # reversed_bits.
        if len(src_value) != 8:
            logging.error(
                'Reverse operand is not the correct length'
            )
            
        reversed_bytes = src_value[6:8] \
                         + src_value[4:6] \
                         + src_value[2:4] \
                         + src_value[0:2]
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            reversed_bytes
        )
        return (next_reg_values, null_registers)
        
    def process_ror(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )
        if src_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Process shift.
        if len(operands) == 2:
            shift_value = self.get_shift_value(next_reg_values, operands[1])
        else:
            shift_value = self.get_shift_value(next_reg_values, operands[2])
        (result, carry) = self.rotate_right(src_value, shift_value)
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_rrx(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        
        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )
        if src_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Process shift.
        (result, carry) = self.rotate_right_with_extend(
            src_value,
            condition_flags['c']
        )
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_rsb(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            return (next_reg_values, condition_flags, null_registers)

        (result, carry, overflow) = \
            self.add_with_carry(add_value, start_value, 1, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_sbc(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            return (next_reg_values, condition_flags, null_registers)

        carry_in = condition_flags['c']
        if carry_in == None: carry_in = 0
        (result, carry, overflow) = \
            self.add_with_carry(start_value, add_value, carry_in, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_stm(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands

        dst_register = operands[0]
        (address, _) = self.get_src_reg_value(next_reg_values, dst_register, 'int')
        if address == None: 
            return (next_reg_values, memory_map, null_registers)
        
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
        return (next_reg_values, memory_map, null_registers)
        
    def process_str(self, ins_address, instruction, current_reg_values, 
                        memory_map, condition_flags, null_registers):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[0], 'hex')
        if src_value == None: 
            return (next_reg_values, memory_map, null_registers)
        
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
            return (next_reg_values, memory_map, null_registers)
            
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
            
        return (next_reg_values, memory_map, null_registers)
        
    def process_strd(self, ins_address, instruction, current_reg_values, 
                            memory_map, condition_flags, null_registers):
        next_reg_values = current_reg_values
        opcode_id = instruction.id
        operands = instruction.operands

        (src_value1, _) = self.get_src_reg_value(next_reg_values, operands[0], 'hex')
        (src_value2, _) = self.get_src_reg_value(next_reg_values, operands[1], 'hex')
        if ((src_value1 == None) and (src_value2 == None)):
            return (next_reg_values, memory_map, null_registers)
            
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
            return (next_reg_values, memory_map, null_registers)
            
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
            
        return (next_reg_values, memory_map, null_registers)
        
    def process_sub(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            start_operand = operands[0]
            add_operand = operands[1]
        else:
            start_operand = operands[1]
            add_operand = operands[2]
            
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        (result, carry, overflow) = \
            self.add_with_carry(start_value, add_value, 1, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if instruction.update_flags == True:
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags, null_registers)

    def process_sxt(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        src_operand = operands[1]
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [src_operand.value.reg],
            [dst_operand]
        )
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None: 
            return (next_reg_values, null_registers)
        
        # This is to make sure we get the correct bytes.
        src_value = src_value.zfill(8)

        if opcode_id == ARM_INS_SXTB:
            src_value = src_value[-2:]
        elif opcode_id == ARM_INS_SXTH:
            src_value = src_value[-4:]
        
        # This is the actual extension.
        extended_value = self.sign_extend(src_value)
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            extended_value
        )
        return (next_reg_values, null_registers)
        
    def process_uxt(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        src_operand = operands[1]
        
        # Update null registers.
        null_registers = self.update_null_registers(
            null_registers,
            [src_operand.value.reg],
            [dst_operand]
        )
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None: 
            return (next_reg_values, null_registers)
        
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
        return (next_reg_values, null_registers)
    
    # =======================================================================
    
    def get_return_trace_obj(self, trace_obj, address):
        prev_address = self.get_previous_address(self.all_addresses, address)
        trace_obj_list = self.generate_return_trace_obj(
            self.master_trace_obj,
            prev_address,
            trace_obj,
            []
        )
        if len(trace_obj_list) > 0:
            trace_obj = trace_obj_list[0]
        return trace_obj

    def generate_return_trace_obj(self, json_tree, branchpoint, trace_obj, output_list):
        for key in json_tree:
            if 'branch_or_end_points' not in json_tree[key]:
                continue
            next_level = json_tree[key]['branch_or_end_points']
            if branchpoint in list(next_level.keys()):
                end_target_obj = next_level[branchpoint]['branch_target']
                for target in end_target_obj:
                    if end_target_obj[target] == trace_obj:
                        new_trace_obj = json_tree[key]
                        if new_trace_obj not in output_list:
                            output_list.append(new_trace_obj)
            else:
                for next_key in next_level:
                    b_target_obj = next_level[next_key]['branch_target']
                    output_list = self.generate_return_trace_obj(
                        b_target_obj,
                        branchpoint,
                        trace_obj,
                        output_list
                    )
        return output_list
                    
    def get_dst_operand(self, operand):
        # This should never actually happen.
        if operand.type != ARM_OP_REG:
            logging.critical('Non-register destination operand!')
            return None
        dst_operand = operand.value.reg
        return dst_operand
        
    def get_src_reg_value(self, current_reg_values, src_operand, dtype='hex',
                            carry_in=None):
        if src_operand.type == ARM_OP_IMM:
            src_value = src_operand.value.imm
            if src_value > 2147483647:
                src_value = np.uint32(src_value)
            else:
                src_value = np.int32(src_value)
        elif src_operand.type == ARM_OP_REG:
            src_register = src_operand.value.reg
            if current_reg_values[src_register] == None:
                return (None, None)
            src_value = self.get_register_bytes(
                current_reg_values,
                src_register,
                dtype
            )
        else:
            logging.critical('Non imm/reg src ' + instruction.op_str)
            return (None, None)

        if carry_in == None:
            src_value = self.convert_type(src_value, dtype)        
            return (src_value, carry_in)
        
        carry = carry_in
        if src_operand.shift.value != 0:
            src_value = self.convert_type(src_value, 'int')
            shift_value = src_operand.shift.value
            shift_type = src_operand.shift.type
            if shift_type == ARM_SFT_ASR:
                (src_value, carry) = self.arithmetic_shift_right(src_value, shift_value)
            elif shift_type == ARM_SFT_LSL:
                (src_value, carry) = self.logical_shift_left(src_value, shift_value)
            elif shift_type == ARM_SFT_LSR:
                (src_value, carry) = self.logical_shift_right(src_value, shift_value)
            elif shift_type == ARM_SFT_ROR:
                (src_value, carry) = self.rotate_right(src_value, shift_value)
            elif shift_type == ARM_SFT_RRX:
                (src_value, carry) = self.rotate_right_with_extend(
                    src_value, carry_in
                )
        else:
            carry = carry_in
        src_value = self.convert_type(src_value, dtype)        
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
                    'Index register is None. Cannot compute memory address.'
                )
                return(src_memory_address, next_reg_values)
                
            offset_value = self.get_register_bytes(
                current_reg_values,
                index_register,
                'int'
            )
            (offset_value, _) = self.logical_shift_left(offset_value, lshift)
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
        # RAM.
        start_ram_address = common_objs.ram_base
        end_ram_address = start_ram_address + common_objs.ram_length
        if ((address >= start_ram_address) 
                and (address <= end_ram_address)):
            return consts.ADDRESS_RAM
        # Firmware.
        start_fw_address = self.all_addresses[0]
        end_fw_address = self.all_addresses[-1]
        if ((address >= start_fw_address) 
                and (address <= end_fw_address)):
            return consts.ADDRESS_FIRMWARE
            
        if memory_map == None:
            return None
        # Stack. Technically, this is a stack/RAM combination.
        stack_addresses = list(memory_map.keys())
        stack_addresses.sort()
        if len(stack_addresses) == 0:
            stack_max = int(common_objs.application_vector_table['initial_sp'])
            stack_min = stack_max
        else:
            stack_max = max(stack_addresses)
            stack_min = min(stack_addresses)
        allowable_min = stack_min - 256
        if ((address >= allowable_min) 
                and (address <= stack_max)):
            return consts.ADDRESS_STACK
        # Default
        return None
    
    def get_register_bytes(self, registers, address, dtype='hex'):
        value = None
        if address in registers:
            value = registers[address]
            
        # Type conversion
        value = self.convert_type(value, dtype)
        return value
        
    def get_value_from_memory(self, memory_map, address, 
                                num_bytes=4, dtype='hex', unprocessed=False):
        address_type = self.get_address_type(address, memory_map)
        src_value = None
        ret_none = False
        if address_type is consts.ADDRESS_FIRMWARE:
            src_value = self.get_firmware_bytes(address, num_bytes, dtype)
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
            ret_none = True
        return (src_value, ret_none)
        
    def get_firmware_bytes(self, address, num_bytes=4, dtype='hex', 
            endian=common_objs.endian):
        address = address - common_objs.app_code_base
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
                mem_value = self.reverse_bytes(data_bytes)
            else:
                mem_value = data_bytes
            mem_value = self.convert_type(mem_value, 'hex')
            
            if value == None:
                value = mem_value
            else:
                value = value + mem_value
            remaining_bytes -= obtained_bytes
            address += obtained_bytes
        # Type conversion.
        value = self.convert_type(value, dtype)
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
                sys.exit(0)
            value = self.get_memory_word(memory_map, address, endian)
        elif (num_bytes == 2):
            if (address%2 != 0):
                logging.error('Misaligned word.')
                sys.exit(0)
            value = self.get_memory_halfword(memory_map, address, endian)
        elif (num_bytes == 1):
            if address not in memory_map:
                value = '00'
            else:
                value = memory_map[address]
        else:
            logging.error('Invalid number of bytes.')
            sys.exit(0)
        value = self.convert_type(value, dtype)
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
                    temp_value = self.convert_type(temp_value, 'hex')
                    temp_halfbytes = len(temp_value)
                    temp_bytes = int(temp_halfbytes/2)
        return temp_bytes

    def store_register_bytes(self, registers, address, value, force_word_length=False):
        if address not in registers:
            return registers
        
        value = self.convert_type(value, 'hex')
        if force_word_length == True: value = value.zfill(8)
        registers[address] = value
        return registers
        
    def store_value_to_memory(self, value, address, memory_map, num_bytes):
        address_type = self.get_address_type(address, memory_map)
        if address_type is consts.ADDRESS_FIRMWARE:
            logging.critical(
                'Memory address is within firmware address range: '
                + '{0:08x}'.format(address)
            )
            return memory_map

        value = self.convert_type(value, 'hex')
        if value == None:
            value = '00' * num_bytes
        value = value.zfill(2*num_bytes)

        # TODO: Big-endian option.
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
        value = self.convert_type(value, 'hex')
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

    def process_memset(self, memory_map, register_object, memset_obj):
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
            logging.warning('memset len specified as 0.')
            return memory_map
        # We don't want to create huge memory maps,
        #  so process only if length is lower than a certain value.
        # We choose the length as the maximum length specified in 
        #  SVC definitions.
        if length > 64:
            logging.debug(
                'Over-large value for length '
                + str(length)
            )
            return memory_map
        value = self.convert_type(value, 'hex')
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
        
    # =======================================================================  
    #-------------------------- Utility functions ---------------------------
    
    def get_previous_address(self, address_obj, address):
        if address_obj == None: return None
        if address == None: return None
        
        if type(address_obj) is dict:
            address_obj = list(address_obj.keys())
            address_obj.sort()
        
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
        if type(address_obj) is dict:
            address_obj = list(address_obj.keys())
            address_obj.sort()
            
        if address not in address_obj:
            for i in range(1,4):
                if (address-i) in address_obj:
                    address = address-i
                    break
        return address
            
    def get_next_address(self, address_obj, ins_address):
        if address_obj == None: return None
        if ins_address == None: return None
        
        if type(address_obj) is dict:
            address_obj = list(address_obj.keys())
            address_obj.sort()
            
        # In the case of stack/RAM, the address we want may not be present.
        # Get the next address for whichever address is lower than given 
        #  address instead.
        if ins_address not in address_obj:
            for i in range(128):
                if (ins_address-i) in address_obj:
                    ins_address = ins_address-i
                    break
        # If even a much lower address is not present, then can't proceed.
        if ins_address not in address_obj: return None
        
        # Find index of the address and get next one up.
        if (address_obj.index(ins_address)) < (len(address_obj) - 1):
            next_address = address_obj[address_obj.index(ins_address) + 1]
        else:
            next_address = None
        return next_address
        
    def reverse_bytes(self, bytes):
        hex_bytes = bytes.hex()
        ba = bytearray.fromhex(hex_bytes)
        ba.reverse()
        reversed_hex = ''.join(format(x, '02x') for x in ba)
        reversed_bytes = bytes.fromhex(reversed_hex)
        return reversed_bytes
    
    def get_numpy_type(self, values):
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
        
    def convert_type(self, value, dtype, byte_length='default'):
        if dtype == 'int':
            if type(value) is int:
                value = value
            elif type(value) is str:
                length = len(value)
                value = int(value, 16)
                if length == 2:
                    if value > 127:
                        value = np.uint8(value)
                    else:
                        value = np.int8(value)
                elif length == 4:
                    if value > 32767:
                        value = np.uint16(value)
                    else:
                        value = np.int16(value)
                elif length == 8:
                    if value > 2147483647:
                        value = np.uint32(value)
                    else:
                        value = np.int32(value)
        elif dtype == 'hex':
            if type(value) is str:
                value = value
            elif type(value) is np.int32:
                value = '{0:08x}'.format(value)
            elif type(value) is np.uint32:
                value = '{0:08x}'.format(value)
            elif type(value) is np.int64:
                value = '{0:08x}'.format(value)
            elif type(value) is int:
                value = '{0:02x}'.format(value)
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
        elif dtype == 'int':
            if type(value) is np.int32:
                value = self.get_binary_representation(value, 32)
            elif type(value) is np.uint32:
                value = self.get_binary_representation(value, 32)
            elif type(value) is np.int64:
                value = self.get_binary_representation(value, 32)
            elif type(value) is int:
                value = self.get_binary_representation(value, 32)
            elif type(value) is np.int16:
                value = self.get_binary_representation(value, 16)
            elif type(value) is np.uint16:
                value = self.get_binary_representation(value, 16)
            elif type(value) is np.int8:
                value = self.get_binary_representation(value, 8)
            elif type(value) is np.uint8:
                value = self.get_binary_representation(value, 8)
            elif type(value) is str:
                bin_len = len(str) * 4
                value = self.get_binary_representation(
                    int(value, 16),
                    bin_len
                )
        return value
        
    def print_memory(self, memory):
        # Sort memory obj.
        memory = {key:memory[key] for key in sorted(memory.keys())}
        string_mem = '{'
        for address in memory:
            string_mem += hex(address)
            string_mem += ':'
            value = self.convert_type(memory[address], 'hex')
            string_mem += str(value)
            string_mem += ','
        string_mem += '}'
        return string_mem

    def get_bit_length(self, value):
        bit_length = None
        if ((type(value) is np.uint32) or (type(value) is np.int32)):
            bit_length = 32
        elif ((type(value) is np.uint16) or (type(value) is np.int16)):
            bit_length = 16
        elif ((type(value) is np.uint8) or (type(value) is np.int8)):
            bit_length = 8
        elif (type(value) is str):
            if len(str) == 8:
                bit_length = 32
            elif len(str) == 4:
                bit_length = 16
            elif len(str) == 2:
                bit_length = 8
        if bit_length == None: 
            logging.error(type(value))
            logging.error('WHAT')
        return bit_length
        
    def get_binary_representation(self, value, length):
        if value == None: return None
        if type(value) is str:
            binary = bin(int('1'+value, 16))[3:]
            binary = binary.zfill(length)
        else:
            binary = np.binary_repr(value, width=length)
        return binary          
        
    def convert_bits_to_type(self, bitstring, dtype):
        if dtype is str:
            hex_value = '%0*x' % ((len(bitstring) + 3) // 4, int(bitstring, 2))
            new_value = hex_value
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
        
    # =======================================================================   
    #----------------------------- Arithmetic ops ---------------------------
    
    def logical_shift_left(self, value, shift):
        """Logical Shift Left
        
        (LSL) moves each bit of a bitstring left by a specified number of bits.
        Zeros are shifted in at the right end of the bitstring.
        Bits that are shifted off the left end of the bitstring are discarded, 
        except that the last such bit can be produced as a carry output.
        """
        if shift == 0:
            return (value, 0)
        bit_length = self.get_bit_length(value)
        
        bits = self.get_binary_representation(value, bit_length)
        extended_bits = bits
        for i in range(shift):
            extended_bits += '0'
            carry_out = extended_bits[0]
            shifted_value = extended_bits[(-1*bit_length):]
            extended_bits = shifted_value
        new_value = self.convert_bits_to_type(shifted_value, type(value))
        carry_out = int(carry_out)
        return (new_value, carry_out)
        
    def logical_shift_right(self, value, shift):
        """Logical Shift Right
        
        (LSR) moves each bit of a bitstring right by a specified number of bits.
        Zeros are shifted in at the left end of the bitstring. 
        Bits that are shifted off the right end of the bitstring are discarded, 
        except that the last such bit can be produced as a carry output.
        """
        if shift == 0:
            return (value, 0)
        bit_length = self.get_bit_length(value)
        bits = self.get_binary_representation(value, bit_length)
        extended_bits = bits
        for i in range(shift):
            extended_bits = '0' + extended_bits
            carry_out = extended_bits[-1]
            shifted_value = extended_bits[0:bit_length]
            extended_bits = shifted_value
        new_value = self.convert_bits_to_type(shifted_value, type(value))
        carry_out = int(carry_out)
        return (new_value, carry_out)
    
    def arithmetic_shift_right(self, value, shift):
        """Arithmetic Shift Right
        
        (ASR) moves each bit of a bitstring right by a specified number of bits. 
        Copies of the leftmost bit are shifted in at the left end of the bitstring. 
        Bits that are shifted off the right end of the bitstring are discarded, 
        except that the last such bit can be produced as a carry output.
        """
        if shift == 0:
            return (value, 0)
        bit_length = self.get_bit_length(value)
        bits = self.get_binary_representation(value, bit_length)
        leftmost_bit = bits[0]
        extended_bits = bits
        for i in range(shift):
            extended_bits = leftmost_bit + extended_bits
            carry_out = extended_bits[-1]
            shifted_value = extended_bits[0:bit_length]
            extended_bits = shifted_value
        new_value = self.convert_bits_to_type(shifted_value, type(value))
        carry_out = int(carry_out)
        return (new_value, carry_out)
        
    def rotate_right(self, value, shift):
        """Rotate Right
        
        (ROR) moves each bit of a bitstring right by a specified number of bits. 
        Each bit that is shifted off the right end of the bitstring is 
        re-introduced at the left end. The last bit shifted off the the right end 
        of the bitstring can be produced as a carry output.
        """
        if shift == 0:
            return (value, 0)
        bit_length = self.get_bit_length(value)
        bits = self.get_binary_representation(value, bit_length)
        shifted_bits = bits
        for i in range(shift):
            rightmost_bit = bits[-1]
            shifted_bits = rightmost_bit + bits
            bits = shifted_bits[0:bit_length]
        new_value = self.convert_bits_to_type(bits, type(value))
        carry_out = int(rightmost_bit)
        return (new_value, carry_out)
        
    def rotate_right_with_extend(self, value, carry_in=None):
        """Rotate Right with Extend
        
        (RRX) moves each bit of a bitstring right by one bit. 
        The carry input is shifted in at the left end of the bitstring. 
        The bit shifted off the right end of the bitstring can be produced 
        as a carry output.
        """
        if carry_in == None: carry_in = '0'
        if type(carry_in) is int: carry_in = str(carry_in)
        bit_length = self.get_bit_length(value)
        bits = self.get_binary_representation(value, bit_length)
        shifted_bits = bits
        carry_out = int(bits[-1])
        shifted_bits = carry_in + bits
        bits = shifted_bits[0:bit_length]
        new_value = self.convert_bits_to_type(bits, type(value))
        return (new_value, carry_out)
        
    def add_with_carry(self, x, y, carry_in=0, num_bits = 32, sub=False):
        """
        bits(N), bit, bit) AddWithCarry(bits(N) x, bits(N) y, bit carry_in)
            unsigned_sum = self.uint(x) + self.uint(y) + self.uint(carry_in);
            signed_sum = self.sint(x) + self.sint(y) + self.uint(carry_in);
            result = unsigned_sum<N-1:0>; // same value as signed_sum<N-1:0>
            carry_out = if self.uint(result) == unsigned_sum then ‘0’ else ‘1’;
            overflow = if self.sint(result) == signed_sum then ‘0’ else ‘1’;
            return (result, carry_out, overflow);
        """
        orig_x = x
        orig_y = y
        if sub == True:
            np_dtype = self.get_numpy_type([x, y])
            y = np.bitwise_not(
                y.astype(np_dtype),
                dtype=np_dtype,
                casting='safe'
            )
        try:
            if num_bits == 32:
                np.seterr(over='ignore')
                uint_x = np.uint32(x)
                np.seterr(over='ignore')
                int_x = np.int32(x)
                np.seterr(over='ignore')
                uint_y = np.uint32(y)
                np.seterr(over='ignore')
                int_y = np.int32(y)
                np.seterr(over='ignore')
                uint_carry_in = np.uint32(carry_in)
            elif num_bits == 16:
                np.seterr(over='ignore')
                uint_x = np.uint16(x)
                np.seterr(over='ignore')
                int_x = np.int16(x)
                np.seterr(over='ignore')
                uint_y = np.uint16(y)
                np.seterr(over='ignore')
                int_y = np.int16(y)
                np.seterr(over='ignore')
                uint_carry_in = np.uint16(carry_in)
            elif num_bits == 8:
                np.seterr(over='ignore')
                uint_x = np.uint8(x)
                np.seterr(over='ignore')
                int_x = np.int8(x)
                np.seterr(over='ignore')
                uint_y = np.uint8(y)
                np.seterr(over='ignore')
                int_y = np.int8(y)
                np.seterr(over='ignore')
                uint_carry_in = np.uint8(carry_in)
                
            np.seterr(over='ignore')
            unsigned_sum = uint_x + uint_y + uint_carry_in
            np.seterr(over='ignore')
            signed_sum = int_x + int_y + uint_carry_in
            
            # Set result.
            np.seterr(over='ignore')
            result = np.uint32(unsigned_sum)
            
            # Set carry.
            np.seterr(over='ignore')
            if np.uint32(result) == unsigned_sum:
                carry_out = 0
            else:
                carry_out = 1

            # Set overflow.
            np.seterr(over='ignore')
            if np.int32(result) == signed_sum:
                overflow = 0
            else:
                overflow = 1
                
            if sub == True:
                existing = result
                if carry_in == 1:
                    if orig_x >= orig_y:
                        carry_out = 1
                if carry_in == 0:
                    if orig_x > orig_y:
                        carry_out = 1
            return (result, carry_out, overflow)
        except:
            return (None, None, None)
        
    def is_zero_bit(self, x):
        for bit in x:
            if bit != '0':
                return 0
        return 1
        
    def sign_extend(self, value, total_bits=32):
        bin_value = bin(int('1'+value, 16))[3:]
        top_bit = bin_value[0]
        length_bits = len(bin_value)
        num_sign_bits = total_bits - length_bits
        extended_bits = ''
        for i in range(num_sign_bits):
            extended_bits += top_bit
        extended_bits += bin_value
        extended_hex = '%0*x' % ((len(extended_bits) + 3) // 4, int(extended_bits, 2))
        return extended_hex

        
    # =======================================================================
    #----------------------------- Queue Handling ---------------------------
    
    def add_to_queue(self, queueItem):
        """Add a function object to queue. """
        self.instruction_queue.append(queueItem)
        return
            
    def queue_handler(self):
        """Call queue handler as long as queue not empty and time available. """
        while ((self.instruction_queue) and (self.time_check()!=True)):
            self.handle_queue()

    def time_check(self):
        """Check if elapsed time is greater than max alowable runtime. """
        elapsed_time = timeit.default_timer() - self.start_time
        if(elapsed_time >= common_objs.max_time):
            return True
        return False
        
    def handle_queue(self):
        """Pop first function object and execute. """            
        function_block = self.instruction_queue.popleft()
        # Execute the method with the provided arguments.
        function_ref = function_block[0]
        function_block.remove(function_ref)
        function_ref(*function_block)
         