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


class RegisterEvaluator:
    def __init__(self, perform_time_check=True):
        self.per_trace_start_time = None
        self.start_time = None
        self.all_addresses = None
        self.instruction_queue = collections.deque()
        self.perform_time_check = perform_time_check
        
    def estimate_reg_values_for_trace_object(self, trace_obj, coi_processor_instance): 
        logging.info('Starting register trace.')
        
        logging.debug('Trace object:\n' + json.dumps(trace_obj, indent=4))

        # Start the timer.
        self.start_time = timeit.default_timer()
            
        self.coi_processor = coi_processor_instance
        self.master_trace_obj = trace_obj
        
        # Get starting point for trace from chain.
        start_points = trace_obj.keys()

        # Get all instruction addresses.
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        self.all_addresses = []
        for address in all_addresses:
            if address < common_objs.app_code_base:
                continue
            self.all_addresses.append(address)

        # Keep track of unhandled instructions.
        self.unhandled = []

        # Get the stack pointer value.
        start_stack_pointer = \
            int(common_objs.application_vector_table['initial_sp'])

        for start_point in start_points:
            if self.total_time_check() == True:
                logging.info('Timeout.')
                break
                
            logging.debug('Start point: ' + hex(start_point))
            
            self.per_trace_start_time = timeit.default_timer()
            
            self.expected_endpoints = []
            endpoint_addresses = self.get_endpoint_ids(
                trace_obj[start_point]['branch_or_end_points']
            )
            for endpoint_address in endpoint_addresses:
                self.expected_endpoints.append(endpoint_address)
            self.num_expected_endpoints = len(self.expected_endpoints)
            self.obtained_endpoints = []
            self.num_obtained_endpoints = 0
            logging.debug('Expected endpoints: ' + str(self.expected_endpoints))
            
            # Keep track of checked traces, to avoid repeating.
            self.checked_paths = {}
            self.global_counter = 0
            
            # Start up instruction queue.
            self.instruction_queue = collections.deque()
        
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
            self.add_to_trace_queue(
                start_point,
                start_point,
                initialised_regs,
                initial_memory,
                condition_flags,
                trace_obj[start_point],
                current_path,
                null_registers
            )
            self.queue_handler()
        
        # Clear all files.
        self.clear_working_files()
        unhandled_str = ''
        for unhandled in self.unhandled:
            if unhandled_str == '':
                unhandled_str = unhandled
            else:
                unhandled_str = unhandled_str + ';' + unhandled
        return unhandled_str
    
    def clear_working_files(self):
        logging.debug('Cleaning up...')
        for filename in os.listdir(common_paths.tmp_path):
            file_path = os.path.join(common_paths.tmp_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(
                    'Failed to delete '
                    + file_path
                    + '. Reason: '
                    + str(e)
                )
        return

    # =======================================================================  
    # ------------------------- Trace Path-Related --------------------------
    
    def trace_cois(self, start_point, register_object,  
                                memory_map, condition_flags, trace_obj, 
                                current_path, null_registers={}, gc=0):
        """"""
        if start_point == None: return None
        # Make sure we aren't branching to the vector table, for some reason.
        code_start_point = common_objs.code_start_address
        # We can get all-0 addresses if we load from non-existing addresses.
        if start_point < (code_start_point): 
            return None
        
        # Get branch points/possible end points. 
        (branch_points, end_points, end_point_obj) = \
            self.get_branch_end_points_from_trace_obj(
                trace_obj
            )
        
        while self.num_obtained_endpoints < self.num_expected_endpoints:
            (ins_address, trace_obj, memory_map, register_object) = \
                self.trace_register_values(start_point, end_points,   
                    register_object, memory_map, condition_flags, trace_obj, 
                    branch_points, current_path, null_registers, gc)
            if trace_obj == None: 
                return
                
            # Check the obtained ID against expected.
            obtained_id = trace_obj['branch_or_end_points'][ins_address]['id']
            if obtained_id not in self.obtained_endpoints:
                self.obtained_endpoints.append(
                    obtained_id
                )
            self.num_obtained_endpoints = len(self.obtained_endpoints)
            logging.debug(
                'Expected endpoints: '
                + str(self.expected_endpoints)
                + ' obtained endpoints: '
                + str(self.obtained_endpoints)
            )
            
            # Process the COI.
            coi_name = end_point_obj[ins_address]
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
                + coi_name
                + ' at '
                + hex(ins_address)
                + '!\n'
                + 'memory: '
                + self.print_memory(memory_map)
                + '\nregisters: '
                + self.print_memory(register_object)
            )
            
            # Process the output and get updated memory map.
            memory_map = self.coi_processor.process_trace_output(
                {coi_name:out_obj}
            )
            memory_map = {
                key:memory_map[key] 
                    for key in sorted(memory_map.keys())
            }
            end_points.remove(ins_address)
            
            # Output of SVC is an error code stored in register r0.
            # Output of function call is unknown.
            #  We assume 0, i.e., no error.
            register_object = self.store_register_bytes(
                register_object,
                ARM_REG_R0,
                '00000000'
            )
            # We've done all the processing we want to, 
            #  for the COI call instruction.
            # So continue to next instruction.
            (ins_address, register_object) = self.update_pc_register(
                ins_address,
                register_object
            )
            if ins_address == None: break
            start_point = ins_address
            
        if self.num_expected_endpoints == self.num_obtained_endpoints:
            logging.debug('Obtained all expected endpoints for this trace.')
            return

    def trace_register_values(self, start_point, end_points, register_object,  
                            memory_map, condition_flags, trace_obj, branch_points, 
                            current_path, null_registers={}, gc=0, exec_last=False):
        logging.debug(  
            'Starting trace at '
            + hex(start_point)
            + ', counter: '
            + str(gc)
        )
        
        # Start from the starting point within assembly,
        #  and follow the instructions along the chain.
        ins_address = start_point
        code_end = self.all_addresses[-1]
        while ins_address <= code_end:
            register_object[ARM_REG_PC] = self.get_pc_value(ins_address)
        
            pre_exec_address = ins_address
            
            # If we have arrived at an end point, then
            #  return the registers and memory map.
            if exec_last == False:
                if ins_address in end_points:
                    return (ins_address, trace_obj, memory_map, register_object)
                
            if ins_address in common_objs.errored_instructions:
                logging.trace(
                    'Errored instruction at '
                    + hex(ins_address)
                    + '. Skipping.'
                )
                (ins_address, register_object) = self.update_pc_register(
                    ins_address,
                    register_object
                )
                if ins_address == None: break
                continue
                
            # We assume that the code must contain ways to skip inline data
            #  (such as via branches), so if we encounter inline data, 
            #  we must have come to end of executable part of function.
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                logging.trace(
                    'Data instruction at '
                    + hex(ins_address)
                    + '. Skipping'
                )
                return (None, None, None, None)

            # Instructions we needn't process (NOP, etc).
            skip_insn = self.check_skip_instruction(ins_address)
            if skip_insn == True:
                logging.trace(
                    'Instruction at '
                    + hex(ins_address)
                    + ' to be skipped.'
                )
                (ins_address, register_object) = self.update_pc_register(
                    ins_address,
                    register_object
                )
                if ins_address == None: break
                continue
            
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            opcode_id = insn.id

            # Debug and trace messages.
            logging.debug('------------------------------------------')
            logging.trace('memory: ' + self.print_memory(memory_map))
            logging.debug('reg: ' + self.print_memory(register_object))
            logging.debug(hex(ins_address) + '  ' + insn.mnemonic + '  ' + insn.op_str)

            # Branches require special processing.
            if opcode_id in [ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, 
                    ARM_INS_CBNZ, ARM_INS_CBZ]:
                (executed_branch, should_execute_next_instruction) = \
                    self.process_branch_instruction(
                        register_object,
                        memory_map,
                        trace_obj,
                        current_path,
                        ins_address,
                        condition_flags,
                        branch_points,
                        null_registers
                    )
                if ((opcode_id == ARM_INS_BL) and (executed_branch == False)):
                    register_object[ARM_REG_R0] = '00000000'
                if should_execute_next_instruction == True:
                    (ins_address, register_object) = self.update_pc_register(
                        ins_address,
                        register_object
                    )
                    if ins_address == None: break
                    continue
                else:
                    logging.trace(
                        'Branch processing indicates that next instruction '
                        + 'should not be executed.'
                    )
                    return (None, None, None, None)
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
                return (None, None, None, None)
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
                return (None, None, None, None)
                
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
                logging.trace(
                    'Register object returned null. Probably POP {PC}'
                )
                return (None, None, None, None)
            (ins_address, register_object) = self.update_pc_register(
                ins_address,
                register_object
            )
            if ins_address == None: break
            
            if exec_last == True:
                if pre_exec_address in end_points:
                    return (pre_exec_address, trace_obj, memory_map, register_object)
        return (None, None, None, None)
    
    def update_pc_register(self, ins_address, register_object):
        if utils.is_valid_code_address(ins_address) != True:
            should_update_pc_value = True
        else:
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if len(insn.operands) == 0:
                should_update_pc_value = True
            else:
                if ((insn.operands[0].type == ARM_OP_REG) 
                        and (insn.operands[0].value.reg == ARM_REG_PC)):
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
        
    def get_branch_end_points_from_trace_obj(self, trace_obj):
        branch_or_end_points = trace_obj['branch_or_end_points']
        branch_points = list(branch_or_end_points.keys())
        branch_points.sort()
        end_point_obj = {}        
        for address in branch_points:
            if branch_or_end_points[address]['is_end'] == True:
                end_point_obj[address] = \
                    branch_or_end_points[address]['coi_name']
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
                and (branch_target not in common_objs.coi_function_blocks)):
            executed_branch = False
            should_execute_next_instruction = True
            logging.debug('Branch has been denylisted')
            return (executed_branch, should_execute_next_instruction)
            
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
            elif func_type == consts.FN_UDIV:
                register_object = self.process_software_udiv(
                    register_object
                )
            executed_branch = True
            should_execute_next_instruction = True
            # These special functions are normally called using BL.
            #  If B is used, then we probably don't want to continue execution.
            if opcode_id == ARM_INS_B:
                next_address = \
                    self.all_addresses[self.all_addresses.index(ins_address) + 1]
                lr_value = int(register_object[ARM_REG_LR], 16)
                if next_address != lr_value:
                    trace_obj = self.get_return_trace_obj(
                        trace_obj,
                        lr_value
                    )
                    logging.debug('Counter: ' + str(self.global_counter))
                    
                    # Branch.
                    self.add_to_trace_queue(
                        ins_address,
                        lr_value,
                        register_object,
                        memory_map,
                        condition_flags,
                        trace_obj,
                        current_path,
                        null_registers
                    )
                    should_execute_next_instruction = False
            return (executed_branch, should_execute_next_instruction)
            
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
            executed_branch = False
            should_execute_next_instruction = True
            return (executed_branch, should_execute_next_instruction)
            
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
        
        
        # If BX, we may need to get previous level of trace obj.
        if opcode_id == ARM_INS_BX:
            trace_obj = self.get_return_trace_obj(
                trace_obj,
                branch_target
            )
        logging.debug('Counter: ' + str(self.global_counter))
        
        # Branch.
        self.add_to_trace_queue(
            ins_address,
            branch_target,
            register_object,
            memory_map,
            condition_flags,
            trace_obj,
            current_path,
            null_registers
        )
        
        executed_branch = True
        return (executed_branch, should_execute_next_instruction)

    def check_should_branch(self, current_path, trace_obj, calling_address, 
                                branch_target):
        # The target might have been set to null on purpose, 
        #  to prevent the branch.
        if (branch_target == None): 
            logging.trace('Null target. Skipping.')
            return (False, None)

        if calling_address in common_objs.errored_instructions:
            logging.trace('Errored instruction. Skipping.')
            return (False, None)
            
        if branch_target < common_objs.code_start_address:
            logging.trace('Target less than code start address. Skipping.')
            return (False, None)
            
        logging.debug('Checking whether we should follow this branch')

        insn = common_objs.disassembled_firmware[calling_address]['insn']
        opcode_id = insn.id
        
        # ----------- Do basic checks first --------------
        
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
        if common_objs.disassembled_firmware[branch_target]['is_data']==True:
            logging.warning(
                'Branch target has been marked as data.'
            )
            return (False, None)

        # If current and target are equal, then it's a perpetual self-loop.
        if calling_address == branch_target:
            logging.trace('Calling address and target are equal. Skipping.')
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
        #  it will have been denylisted.
        if ((target_function_block in common_objs.denylisted_functions)
                and (target_function_block not in common_objs.coi_function_blocks)):
            logging.debug('Target function block has been denylisted.')
            return (False, None)
        
        # The Reset Handler has a lot of self-looping. Avoid.
        reset_handler = int(common_objs.application_vector_table['reset'])
        if curr_function_block == reset_handler:
            if curr_function_block == target_function_block:
                logging.debug('Avoiding internal loops within Reset Handler.')
                return (False, None)
            # We also want to avoid bl to anything other than what is in 
            #  trace object, IF the caller is the reset handler.
            #elif calling_address not in trace_obj['branch_or_end_points']:
            #    logging.debug('Avoiding external branches from Reset Handler.')
            #    return (False, None)
            
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
            'Branching with counter: '  
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
        # To bypass conditional checks, we simply return None.
        # This forces the conditional branch to execute both paths.
        if common_objs.bypass_all_conditional_checks == True:
            return None
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
            
    def check_skip_instruction(self, address):
        if utils.is_valid_code_address(address) != True:
            return True
        address_object = common_objs.disassembled_firmware[address]
        if address_object['insn'].id in [ARM_INS_NOP, ARM_INS_INVALID]:
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
            next_reg_values
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
            # The only way we would have got to this point is if
            #  a register value was null. Which would mean the alternative
            #  path would also have been taken (i.e., the skip address).
            #  So we can safely skip this.
            return
        else:
            branch_address = table_branch_addresses[actual_value]
            
        if branch_address not in common_objs.disassembled_firmware:
            logging.critical(
                'Unable to index into table. '
                + 'Address: '
                + hex(branch_address)
            )
            return
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
            new_path = current_path
            
        debug_msg += (' with counter: ' + str(self.global_counter))
        logging.debug(debug_msg)
        
        self.add_to_trace_queue(
            ins_address,
            branch_address,
            next_reg_values,
            memory_map,
            condition_flags,
            trace_obj,
            new_path,
            null_registers
        )   
            
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
    
    def get_table_branch_register_comparison_value(self, ins_address):
        insn = common_objs.disassembled_firmware[ins_address]['insn']
        opcode_id = insn.id
        operands = insn.operands

        index_register = operands[0].value.mem.index
        
        address = ins_address
        
        comparison_value = None
        comp_address = None
        for i in range(5):
            address = utils.get_previous_address(self.all_addresses, address)
            if utils.is_valid_code_address(address) != True:
                continue
            prev_insn = common_objs.disassembled_firmware[address]
            if prev_insn['insn'].id != ARM_INS_CMP:
                continue
            if prev_insn['insn'].operands[0].value.reg != index_register:
                continue
            comp_address = address
            comparison_value = prev_insn['insn'].operands[1].value.imm
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
            if utils.is_valid_code_address(address):
                continue
            insn = common_objs.disassembled_firmware[address]['insn']
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
                _, _ = self.process_branch_instruction(
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
        self.add_to_trace_queue(
            original_address,
            branching_address,
            next_reg_values,
            memory_map,
            condition_flags,
            trace_obj,
            current_path,
            null_registers
        )
        
    # =======================================================================  
    # ----------------------- Instruction Processing ------------------------
    
    def process_reg_values_for_instruction(self, register_object, memory_map, 
                                trace_obj, current_path, ins_address, 
                                condition_flags, null_registers):
        if ins_address in common_objs.errored_instructions:
            return (None, None, None, None)
        instruction = common_objs.disassembled_firmware[ins_address]['insn']
        if instruction == None:
            return (None, None, None, None)
            
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
        elif instruction.id == ARM_INS_MLA:
            (register_object, condition_flags, null_registers) = self.process_mla(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_MLS:
            (register_object, condition_flags, null_registers) = self.process_mls(
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
        elif instruction.id == ARM_INS_RBIT:
            (register_object, null_registers) = self.process_rbit(
                ins_address,
                instruction,
                register_object,
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
        elif instruction.id == ARM_INS_REV16:
            (register_object, null_registers) = self.process_rev16(
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
        elif instruction.id == ARM_INS_UBFX:
            (register_object, null_registers) = self.process_ubfx(
                ins_address,
                instruction,
                register_object,
                condition_flags,
                null_registers
            )
        elif instruction.id == ARM_INS_UDIV:
            (register_object, null_registers) = self.process_udiv(
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
            # If we don't do this, R0 retains old taints.
            if ARM_REG_R0 in null_registers: del null_registers[ARM_REG_R0]
        else:
            if ('dsb' not in instruction.mnemonic):
                if instruction.mnemonic not in self.unhandled:
                    self.unhandled.append(instruction.mnemonic)
            return (register_object, memory_map, condition_flags, null_registers)
        return (register_object, memory_map, condition_flags, null_registers)

    def update_null_registers(self, null_registers, src_ops, dst_ops):
        tainted = False
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
                tainted = True
                for dst_op in dst_ops:
                    logging.debug(
                        'Register '
                        + str(dst_op)
                        + ' tainted by null register '
                        + str(src_op)
                    )
                    null_registers[dst_op] = {}
                break
        return (null_registers, tainted)
    
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        # Get values.
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)

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
        
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
            
        # Get values.
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values,
            add_operand,
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
        (result, carry, overflow) = binops.add_with_carry(start_value, add_value)

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        pc_value = self.get_mem_access_pc_value(ins_address)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )        
        if add_value == None: 
            null_registers[dst_operand] = {}
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, and_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (and_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            and_operand, 
            'int',
            condition_flags['c']
        )
        if and_value == None:
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
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
        if ((instruction.update_flags == True) and (tainted == False)):
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
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]
            
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [src_operand.value.reg, shift_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        (result, carry) = binops.arithmetic_shift_right(src_value, shift_value)
        if result == None: 
            null_registers[dst_operand] = {}
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
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
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        return (next_reg_values, null_registers)
    
    def process_bfi(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [dst_operand, operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (original_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[0],
            'int'
        )
        if original_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[1],
            'int'
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, not_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (not_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            not_operand, 
            'int',
            condition_flags['c']
        )
        if not_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)

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
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [src_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        if common_objs.null_value_handling != consts.NULL_HANDLING_NONE:
            if (operands[0].value.reg) in null_registers:
                condition_flags = self.initialise_condition_flags()
                return (condition_flags, null_registers)
            if operands[1].type == ARM_OP_REG:
                if (operands[1].value.reg) in null_registers:
                    condition_flags = self.initialise_condition_flags()
                    return (condition_flags, null_registers)
        
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, orr_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
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
        if ((instruction.update_flags == True) and (tainted == False)):
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
            if common_objs.null_value_handling == consts.NULL_HANDLING_LOOSE:
                address_type = self.get_address_type(address)
                if ((address_type != consts.ADDRESS_FIRMWARE) 
                        and (address_type != consts.ADDRESS_DATA) 
                        and (address_type != consts.ADDRESS_RAM)):
                    logging.debug(
                        'LDR source is unavailable. Register '
                        + str(dst_operand)
                        + ' marked as null.'
                    )
                    null_registers[dst_operand] = {}
            elif common_objs.null_value_handling == consts.NULL_HANDLING_STRICT:
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
                pc_target = reg_value
                if pc_target != None:
                    if pc_target % 2 == 1:
                        pc_target = pc_target - 1
                logging.debug('PC branch to ' + hex(pc_target))
                trace_obj = self.get_return_trace_obj(
                    trace_obj,
                    pc_target
                )
                
                # Always follow branch?
                self.add_to_trace_queue(
                    ins_address,
                    pc_target,
                    next_reg_values,
                    memory_map,
                    condition_flags,
                    trace_obj,
                    current_path,
                    null_registers
                )
                return(None, None, None)
                
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
            null_registers[dst_operand] = {}
            logging.error('Null src address: ' + hex(ins_address))
            return (next_reg_values, memory_map, null_registers)

        # If dst_operand is PC, then it causes branch.
        if dst_operand == ARM_REG_PC:
            pc_target = self.get_register_bytes(next_reg_values, dst_operand, 'int')
            if pc_target != None:
                if pc_target % 2 == 1:
                    pc_target = pc_target -1
            logging.debug('PC branch to ' + hex(pc_target))
            trace_obj = self.get_return_trace_obj(
                trace_obj,
                pc_target
            )
            
            self.add_to_trace_queue(
                ins_address,
                pc_target,
                next_reg_values,
                memory_map,
                condition_flags,
                trace_obj,
                current_path,
                null_registers
            )
            return(None, None, null_registers)
            
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
        
        (src_value, null_value) = self.get_value_from_memory(
            memory_map,
            src_memory_address,
            unprocessed=True
        )
        logging.debug('Loaded value: ' + str(src_value))
        
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
            src_value = binops.sign_extend(src_value)
        
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
            null_registers[dst_operand1] = {}
            null_registers[dst_operand2] = {}
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
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]
            
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [src_operand.value.reg, shift_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        (result, carry) = binops.logical_shift_left(src_value, shift_value)
        if result == None: 
            null_registers[dst_operand] = {}
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
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
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]
            
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [src_operand.value.reg, shift_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        (result, carry) = binops.logical_shift_right(src_value, shift_value)
        if result == None: 
            null_registers[dst_operand] = {}
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_mla(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        operand1 = operands[1]
        operand2 = operands[2]
        accumulateop = operands[3]
           
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operand1.value.reg, operand2.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (value1, _) = self.get_src_reg_value(next_reg_values, operand1, 'int')
        if value1 == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (value2, _) = self.get_src_reg_value(next_reg_values, operand2, 'int')
        if value2 == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (accumulate, _) = self.get_src_reg_value(next_reg_values, accumulateop, 'int')
        if accumulate == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)

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
        if ((instruction.update_flags == True) and (tainted == False)):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_mls(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        operand1 = operands[1]
        operand2 = operands[2]
        accumulateop = operands[3]
           
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operand1.value.reg, operand2.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (value1, _) = self.get_src_reg_value(next_reg_values, operand1, 'int')
        if value1 == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (value2, _) = self.get_src_reg_value(next_reg_values, operand2, 'int')
        if value2 == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (accumulate, _) = self.get_src_reg_value(next_reg_values, accumulateop, 'int')
        if accumulate == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)

        value1 = getattr(value1, "tolist", lambda: value1)()
        value2 = getattr(value2, "tolist", lambda: value2)()
        accumulate = getattr(accumulate, "tolist", lambda: accumulate)()
        mul_value = value1 * value2
        mul_value = accumulate - mul_value 
        mul_value = '{0:08x}'.format(mul_value)
        mul_value = mul_value.zfill(8)
        result = mul_value[-8:]

        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_mov(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        if len(operands) != 2:
            logging.error('More than 2 ops ' + instruction.op_str)
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (result, carry) = self.get_src_reg_value(next_reg_values, operands[1])
        if operands[1].type == ARM_OP_REG: carry = None
        if result == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operand1.value.reg, operand2.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (value1, _) = self.get_src_reg_value(next_reg_values, operand1, 'int')
        if value1 == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (value2, _) = self.get_src_reg_value(next_reg_values, operand2, 'int')
        if value2 == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)

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
        if ((instruction.update_flags == True) and (tainted == False)):
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
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int',
            condition_flags['c']
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
        np_dtype = utils.get_numpy_type([src_value])
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
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, orr_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
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
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, orr_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (orr_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            orr_operand, 
            'int',
            condition_flags['c']
        )
        if orr_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
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
        if ((instruction.update_flags == True) and (tainted == False)):
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
            if pc_target != None:
                if pc_target % 2 == 1:
                    pc_target = pc_target - 1
            logging.debug('Returning to ' + str(pc_target) + ' (POP PC)')
            # Since POP is essentially returning, we needn't do a branch check?
            # We need to get a revised trace_obj.
            trace_obj = self.get_return_trace_obj(
                trace_obj,
                pc_target
            )
            self.add_to_trace_queue(
                ins_address,
                pc_target,
                next_reg_values,
                memory_map,
                condition_flags,
                trace_obj,
                current_path,
                null_registers
            )
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
        
    def process_rbit(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[1])
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
        # reversed_bits.
        src_bits = utils.get_binary_representation(src_value, 32)
        reversed_bits = src_bits[::-1]
            
        reversed_bytes = utils.convert_bits_to_type(reversed_bits, 'hex')
        
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            reversed_bytes
        )
        return (next_reg_values, null_registers)
        
    def process_rev(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[1], 'hex')
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        return (next_reg_values, null_registers)
        
    def process_rev16(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, _) = self.get_src_reg_value(next_reg_values, operands[1], 'hex')
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        return (next_reg_values, null_registers)
        
    def process_ror(self, ins_address, instruction, current_reg_values, 
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
            
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, condition_flags, null_registers)
        
        if len(operands) == 2:
            src_operand = operands[0]
            shift_operand = operands[1]
        else:
            src_operand = operands[1]
            shift_operand = operands[2]
            
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [src_operand.value.reg, shift_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()

        (src_value, carry) = self.get_src_reg_value(next_reg_values, src_operand, 'int')
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        # Process shift.
        shift_value = self.get_shift_value(next_reg_values, shift_operand)
        if shift_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
            
        (result, carry) = binops.rotate_right(src_value, shift_value)
        if result == None: 
            null_registers[dst_operand] = {}
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, carry) = self.get_src_reg_value(
            next_reg_values, 
            operands[1], 
            'int'
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
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
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)

        (result, carry, overflow) = \
            binops.add_with_carry(add_value, start_value, 1, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)

        carry_in = condition_flags['c']
        if carry_in == None: carry_in = 0
        (result, carry, overflow) = \
            binops.add_with_carry(start_value, add_value, carry_in, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
            condition_flags = self.update_condition_flags(
                condition_flags,
                result,
                carry,
                overflow
            )
        return (next_reg_values, condition_flags, null_registers)
        
    def process_sbfx(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [dst_operand, operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
            
        (src_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[1]
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        return (next_reg_values, null_registers)
        
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [start_operand.value.reg, add_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (start_value, _) = self.get_src_reg_value(
            next_reg_values, 
            start_operand, 
            'int'
        )
        if start_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        (add_value, _) = self.get_src_reg_value(
            next_reg_values, 
            add_operand, 
            'int',
            condition_flags['c']
        )
        if add_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, condition_flags, null_registers)
        
        (result, carry, overflow) = \
            binops.add_with_carry(start_value, add_value, 1, sub=True)
            
        next_reg_values = self.store_register_bytes(
            next_reg_values,
            dst_operand,
            result
        )
        if ((instruction.update_flags == True) and (tainted == False)):
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [src_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        return (next_reg_values, null_registers)
        
    def process_ubfx(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [dst_operand, operands[1].value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
            
        (src_value, _) = self.get_src_reg_value(
            next_reg_values,
            operands[1]
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        
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
        return (next_reg_values, null_registers)
            
    def process_udiv(self, ins_address, instruction, current_reg_values,
                            condition_flags, null_registers):
        next_reg_values = current_reg_values
        operands = instruction.operands
        opcode_id = instruction.id
        
        dst_operand = self.get_dst_operand(operands[0])
        if dst_operand == None: 
            return (next_reg_values, null_registers)
        
        if len(operands) == 2:
            numerator_operand = operands[0]
            denominator_operand = operands[1]
        else:
            numerator_operand = operands[1]
            denominator_operand = operands[2]
            
        # Update null registers.
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [numerator_operand.value.reg, denominator_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
            
        (numerator, _) = self.get_src_reg_value(
            next_reg_values, 
            numerator_operand, 
            'int'
        )
        if numerator == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
        (denominator, _) = self.get_src_reg_value(
            next_reg_values, 
            denominator_operand, 
            'int'
        )
        if denominator == None: 
            null_registers[dst_operand] = {}
            return (next_reg_values, null_registers)
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
        (null_registers, tainted) = self.update_null_registers(
            null_registers,
            [src_operand.value.reg],
            [dst_operand]
        )
        if tainted == True: 
            condition_flags = self.initialise_condition_flags()
        
        (src_value, _) = self.get_src_reg_value(
            next_reg_values, 
            src_operand, 
            'hex'
        )
        if src_value == None: 
            null_registers[dst_operand] = {}
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
        prev_address = utils.get_previous_address(self.all_addresses, address)
        trace_obj_list = self.generate_return_trace_obj(
            self.master_trace_obj,
            prev_address,
            trace_obj,
            []
        )
        if len(trace_obj_list) > 0:
            trace_obj = trace_obj_list[0]
            if common_objs.bypass_all_conditional_checks == True:
                return trace_obj
                
            logging.debug(
                'Re-evaluating endpoints based on reachability '
                + 'for trace object '
                + str(trace_obj)
                + ' and address '
                + str(prev_address)
            )
            address_obj = trace_obj['branch_or_end_points'][prev_address]
            branch_target = list(address_obj['branch_target'].keys())[0]
            expected_obj = address_obj['branch_target'][branch_target]
            expected_obj = expected_obj['branch_or_end_points']
            expected_ids = self.get_endpoint_ids(expected_obj)
            for expected_id in expected_ids:
                if expected_id not in self.obtained_endpoints:
                    if expected_id in self.expected_endpoints:
                        self.expected_endpoints.remove(expected_id)
            self.num_expected_endpoints = len(self.expected_endpoints)
            logging.debug(
                'Re-evaluated expected endpoints: '
                + str(self.expected_endpoints)
            )
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
        else:
            logging.critical('Non imm/reg src ' + instruction.op_str)
            return (None, None)

        if carry_in == None:
            src_value = utils.convert_type(src_value, dtype)        
            return (src_value, carry_in)
        
        carry = carry_in
        if src_operand.shift.value != 0:
            src_value = utils.convert_type(src_value, 'int')
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
        src_value = utils.convert_type(src_value, dtype)        
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
        # DATA
        data_region = list(common_objs.data_region.keys())
        data_region.sort()
        if len(data_region) > 0:
            start_data_region = data_region[0]
            end_data_region = data_region[-1]
            if ((address >= start_data_region) 
                    and (address <= end_data_region)):
                return consts.ADDRESS_DATA
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
        value = utils.convert_type(value, dtype)
        return value
        
    def get_value_from_memory(self, memory_map, address, 
                                num_bytes=4, dtype='hex', unprocessed=False):
        address_type = self.get_address_type(address, memory_map)
        src_value = None
        ret_none = False
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
            ret_none = True
        return (src_value, ret_none)
        
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
        address_type = self.get_address_type(address, memory_map)
        if address_type is consts.ADDRESS_FIRMWARE:
            logging.critical(
                'Memory address is within firmware address range: '
                + '{0:08x}'.format(address)
            )
            return memory_map

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

    # =======================================================================
    #----------------------------- Queue Handling ---------------------------
    def add_to_trace_queue(self, source, target, register_object, 
                                memory_map, condition_flags, trace_obj, 
                                current_path, null_registers):
        """Check whether a trace item is to be added to queue."""
        # Generate pickle file.
        # Generate dictionary. Do not include elements that *will* change
        #  with every new path (i.e., counter and traced path).
        pickle_object = {
            'source': source,
            'start': target,
            'reg': utils.sort_dict_keys(register_object),
            'ram': utils.sort_dict_keys(memory_map),
            'condition': utils.sort_dict_keys(condition_flags),
            'null': utils.sort_dict_keys(null_registers)
        }

        pickle_bytes = pickle.dumps(pickle_object)
        m = hashlib.sha256(pickle_bytes)
        pickle_name = m.hexdigest()
        
        # Add the counter and path.
        pickle_object['counter'] = self.global_counter
        pickle_object['path'] =  current_path
        pickle_object['trace'] = trace_obj
        
        pickle_file = os.path.join(
            common_paths.tmp_path,
            pickle_name + '.pkl'
        )
        
        # If we have run the same trace before, with same set of parameters,
        #  then don't re-run.
        if pickle_file in self.instruction_queue:
            return
        
        # Write pickled representation of data to file.
        with open(pickle_file, 'wb') as f:
            pickle.dump(pickle_object, f)
            
        # Add to queue.
        self.instruction_queue.append(pickle_file)
        self.global_counter += 1
            
    def queue_handler(self):
        """Call queue handler as long as queue not empty and time available. """
        while ((self.instruction_queue) and (self.time_check()!=True)):
            if self.num_obtained_endpoints == self.num_expected_endpoints:
                logging.debug('Obtained the required endpoints')
                return
            self.handle_queue()

    def total_time_check(self):
        if common_objs.max_time != 0:        
            elapsed_time = timeit.default_timer() - self.start_time
            if (elapsed_time >= common_objs.max_time):
                return True
        return False
        
    def time_check(self):
        """Check if elapsed time is greater than max allowable runtime. """
        if self.perform_time_check == False:
            return False
        if common_objs.per_trace_max_time != 0:
            per_trace_elapsed_time = timeit.default_timer() - self.per_trace_start_time
            if (per_trace_elapsed_time >= common_objs.per_trace_max_time):
                return True
        
        if common_objs.max_time != 0:        
            elapsed_time = timeit.default_timer() - self.start_time
            if (elapsed_time >= common_objs.max_time):
                return True
        
        return False
        
    def handle_queue(self):
        """Pop first function object and execute. """            
        # Get the arguments
        pickle_path = self.instruction_queue.popleft()
        argument_list = self.get_pickled_arguments(pickle_path)
        
        # Execute the method with the provided arguments.
        self.trace_cois(*argument_list)
        
    def get_pickled_arguments(self, pickle_path):
        """Load pickled data from file."""
        # Get pickled data.
        with open(pickle_path, 'rb') as f:
            pickled_data = pickle.load(f)
        
        # Build the argument list.
        argument_list = []
        argument_list.append(pickled_data['start'])
        argument_list.append(pickled_data['reg'])
        argument_list.append(pickled_data['ram'])
        argument_list.append(pickled_data['condition'])
        argument_list.append(pickled_data['trace'])
        argument_list.append(pickled_data['path'])
        argument_list.append(pickled_data['null'])
        argument_list.append(pickled_data['counter'])
        
        # We no longer need the file. Delete it to save space.
        os.remove(pickle_path)
        return argument_list
        
    def get_endpoint_ids(self, dictionary):
        endpoints = []
        for k in dictionary:
            if dictionary[k]['is_end'] == False:
                for branch in dictionary[k]['branch_target']:
                    endpoints = endpoints + self.get_endpoint_ids(
                        dictionary[k]['branch_target'][branch]['branch_or_end_points']
                    )
            else:
                endpoints.append(dictionary[k]['id'])
        return endpoints
        