import os
import sys
import struct
import logging
from capstone import *
from capstone.arm import *
from svcxtract.common import paths as common_paths
from svcxtract.core import utils
from svcxtract.core import consts
from svcxtract.common import objects as common_objs
from svcxtract.core.register_evaluator import RegisterEvaluator

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
# Turn on SKIPDATA mode - this is needed!
md.skipdata = True
md.detail = True


class FirmwareDisassembler:
    def __init__(self):
        self.reg_eval = RegisterEvaluator()
        
    def create_disassembled_obj(self, store=True):
        disassembled_fw = self.disassemble_fw()

        # This is for the initial fw checks.
        if store!= True:
            return disassembled_fw
        
        # Add dummy keys, to handle Capstone issues.
        disassembled_firmware_with_dummy_keys = self.add_dummy_keys(
            disassembled_fw
        )
        disassembled_fw = None
        
        # Now add firmware to common_objs.
        common_objs.disassembled_firmware = disassembled_firmware_with_dummy_keys
        disassembled_firmware_with_dummy_keys = None
        
        # See if any data values are being interpreted as instructions.
        self.check_data_instructions()
            
        # Remove dummy keys.
        common_objs.disassembled_firmware = self.remove_dummy_keys(
            common_objs.disassembled_firmware
        )

        # Check again for inline data, but this time using inline addresses.
        self.check_inline_address_instructions()
        
        # Create backlinks.
        common_objs.disassembled_firmware = self.check_valid_branches(
            common_objs.disassembled_firmware
        )
        
        # Mark out last known instruction.
        common_objs.disassembled_firmware = self.mark_last_instruction(
            common_objs.disassembled_firmware
        )
        
    def disassemble_fw(self):
        logging.info(
            'Disassembling firmware using Capstone '
            + 'using disassembly start address: '
            + hex(common_objs.disassembly_start_address)
        )
        
        disassembled_fw = {}
        with open(common_paths.path_to_fw, 'rb') as f:
            byte_file = f.read()
            # Save firmware bytes.
            common_objs.core_bytes = byte_file
        
        disassembled = md.disasm(
            byte_file,
            common_objs.disassembly_start_address
        )
        
        trace_msg = 'Disassembled firmware instructions:\n'
        for instruction in disassembled:
            disassembled_fw[instruction.address] = {
                'insn': instruction,
                'is_data': False
            }
            bytes = ''.join('{:02x}'.format(x) for x in instruction.bytes)
            trace_msg += '\t\t\t\t0x%x:\t%s\t%s\t%s\n' %(instruction.address,
                                            bytes,
                                            instruction.mnemonic,
                                            instruction.op_str)
        logging.trace(trace_msg)
        return disassembled_fw
        
    def add_dummy_keys(self, disassembled_fw):
        logging.debug('Creating dummy keys for disassembled object.')
        # Add dummy keys to the object, to prevent errors later.
        all_keys = list(disassembled_fw.keys())
        first_key = all_keys[0]
        last_key = all_keys[-1]
        disassembled_fw_with_dummy_keys = {}
        for index in range(first_key, last_key, 2):
            if index in disassembled_fw:
                disassembled_fw_with_dummy_keys[index] = disassembled_fw[index]
            else:
                disassembled_fw_with_dummy_keys[index] = {
                    'insn': None,
                    'is_data': False
                }
        
        return disassembled_fw_with_dummy_keys
        
    def remove_dummy_keys(self, disassembled_fw):
        new_fw = {}
        for ins_address in disassembled_fw:
            if ((disassembled_fw[ins_address]['insn'] == None) and 
                    (disassembled_fw[ins_address]['is_data'] == False)):
                continue
            new_fw[ins_address] = disassembled_fw[ins_address]
        return new_fw
        
    def check_data_instructions(self):
        """Checks to see if any instructions are actually data values."""
        logging.debug(
            'Checking for presence of inline data (data as instructions).'
        )

        # Read in data from the Reset Handler.
        self.analyse_data_regions_via_reset_handler()
        
        for ins_address in common_objs.disassembled_firmware:
            if ins_address < common_objs.code_start_address:
                continue
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn == None:
                continue

            # If ID is 0, then it may mean inline data.
            if insn.id == ARM_INS_INVALID:
                common_objs.disassembled_firmware[ins_address]['is_data'] = True
                continue
   
            # Table branch indices.
            if insn.id in [ARM_INS_TBB, ARM_INS_TBH]:
                index_register = insn.operands[0].value.mem.index
                pc_address = ins_address + 4
                address = ins_address
                for i in range(5):
                    address -= 2
                    if common_objs.disassembled_firmware[address]['is_data'] == True:
                        continue
                    if common_objs.disassembled_firmware[address]['insn'] == None:
                        continue
                    prev_insn = common_objs.disassembled_firmware[address]['insn']
                    if prev_insn.id != ARM_INS_CMP:
                        continue
                    if prev_insn.operands[0].value.reg != index_register:
                        continue
                    comp_value = prev_insn.operands[1].value.imm
                    break
                mul_factor = 1
                if insn.id == ARM_INS_TBH:
                    mul_factor = 2
                table_branch_max = pc_address + (comp_value * mul_factor) + 2
                while pc_address < table_branch_max:
                    logging.debug(
                        'Marking '
                        + hex(pc_address)
                        + ' as branch index table.'
                    )
                    common_objs.disassembled_firmware[pc_address]['is_data'] = True
                    common_objs.disassembled_firmware[pc_address]['table_index'] = True
                    common_objs.disassembled_firmware[pc_address]['insn'] = None
                    pc_address += 2
                continue
            
            # If the instruction is not a valid LDR instruction, then don't bother.
            if self.check_valid_pc_ldr(insn) != True:
                continue
            curr_pc_value = self.reg_eval.get_mem_access_pc_value(ins_address)
                
            # Target address is PC + offset.
            operands = insn.operands
            ldr_target = curr_pc_value + operands[1].mem.disp

            if ldr_target not in common_objs.disassembled_firmware:
                if ins_address not in common_objs.errored_instructions:
                    common_objs.errored_instructions.append(ins_address)
                continue
     
            # If we have already marked the data at the target address,
            #  then we needn't process it again.
            if common_objs.disassembled_firmware[ldr_target]['is_data'] == True:
                continue
            
            # Get data bytes at target address.
            data_bytes = self.get_ldr_target_data_bytes(ldr_target)
            if data_bytes == consts.ERROR_INVALID_INSTRUCTION:
                if ins_address not in common_objs.errored_instructions:
                    common_objs.errored_instructions.append(ins_address)
                continue
            
            logging.debug(
                'Marking '
                + hex(ldr_target)
                + ' as data called from '
                + hex(ins_address)
            )
                    
            # Now that we know the target address contains data, 
            #  not instructions, we set is_data to True, 
            #  and nullify instruction.
            common_objs.disassembled_firmware[ldr_target]['is_data'] = True
            common_objs.disassembled_firmware[ldr_target]['insn'] = None   
            
            if insn.id == ARM_INS_LDR:
                # If we don't have a 4-byte word, then we need to get remaining
                #  bytes from next "instruction".
                if len(data_bytes) < 4:
                    data_bytes = self.get_data_from_next_instruction(
                        ins_address,
                        ldr_target,
                        data_bytes
                    )
                    if data_bytes == consts.ERROR_INVALID_INSTRUCTION:
                        if ins_address not in common_objs.errored_instructions:
                            common_objs.errored_instructions.append(ins_address)
                        continue
                ordered_bytes = struct.unpack('<I', data_bytes)[0]
                common_objs.disassembled_firmware[ldr_target]['data'] = ordered_bytes
            elif insn.id in [ARM_INS_LDRH, ARM_INS_LDRSH]:
                if len(data_bytes) == 2:
                    ordered_bytes = struct.unpack('<H', data_bytes)[0]
                else:
                    logging.error('LDRH target does not have exactly two bytes.')
                    data_bytes = data_bytes[0:2]
                    ordered_bytes = struct.unpack('<H', data_bytes)[0]
                common_objs.disassembled_firmware[ldr_target]['data'] = ordered_bytes
            else:
                continue

    def analyse_data_regions_via_reset_handler(self):
        reset_handler_address = common_objs.application_vector_table['reset']
        address = reset_handler_address - 2
        max_address = address + 30
        ram_min = common_objs.ram_base
        ram_max = ram_min + common_objs.ram_length
        data_start_firmware_address = ''
        data_start_real_address = ''
        while address < max_address:
            address += 2
            insn = common_objs.disassembled_firmware[address]['insn']
            if insn == None:
                continue
            
            # If there's inline data, we've probably come to the end.
            if insn.id == ARM_INS_INVALID:
                common_objs.disassembled_firmware[address]['is_data'] = True
                break
                
            if self.check_valid_pc_ldr(insn) != True:
                continue
                
            if insn.id == ARM_INS_LDR:
                curr_pc_value = self.reg_eval.get_mem_access_pc_value(address)
                
                # Target address is PC + offset.
                operands = insn.operands
                ldr_target = curr_pc_value + operands[1].mem.disp
                ldr_value = self.reg_eval.get_firmware_bytes(ldr_target, 4)
                ldr_value = int(ldr_value, 16)
                common_objs.disassembled_firmware[ldr_target]['is_data'] = True
                common_objs.disassembled_firmware[ldr_target]['data'] = ldr_value
                if ldr_value in common_objs.disassembled_firmware:
                    if data_start_firmware_address == '':
                        data_start_firmware_address = ldr_value
                    else:
                        # We will use the largest value as start address.
                        if ldr_value < data_start_firmware_address:
                            continue
                        data_start_firmware_address = ldr_value
                    logging.debug(
                        'Possible start of .data is at: ' 
                        + hex(ldr_value)
                    )
                elif((ldr_value >= ram_min) and (ldr_value <= ram_max)):
                    if data_start_real_address == '':
                        data_start_real_address = ldr_value
                    else:
                        # We will use smallest value as address.
                        if ldr_value > data_start_real_address:
                            continue
                        else:
                            data_start_real_address = ldr_value
                    logging.debug(
                        'Possible start address for .data: ' 
                        + hex(ldr_value)
                    )
        if data_start_firmware_address == '':
            return
        if data_start_real_address == '':
            return
        all_addresses = list(common_objs.disassembled_firmware.keys())
        last_address = all_addresses[-1]
        if data_start_firmware_address >= last_address:
            return
        data_region = {}
        fw_address = data_start_firmware_address
        real_address = data_start_real_address
        while fw_address <= last_address:
            if real_address % 4 == 0:
                data_region_value = \
                    self.reg_eval.get_firmware_bytes(
                        fw_address, 
                        4,
                        endian='big'
                    )
                data_region[real_address] = data_region_value
            common_objs.disassembled_firmware[fw_address]['is_data'] = True
            common_objs.disassembled_firmware[fw_address]['data'] = \
                int(data_region_value, 16)
            real_address += 2
            fw_address += 2
        common_objs.data_region = data_region
        logging.debug(common_objs.data_region)
    
    def get_data_from_next_instruction(self, ins_address, ldr_target, data_bytes):
        if (ldr_target+2) not in common_objs.disassembled_firmware:
            logging.error(
                'Required 4 bytes not found. '
                + 'See ldr target referenced from: '
                + hex(ins_address)
            )
            return consts.ERROR_INVALID_INSTRUCTION
            
        # Get the next "instruction".
        if common_objs.disassembled_firmware[ldr_target+2]['insn'] != None:
            next_ins_bytes = \
                common_objs.disassembled_firmware[ldr_target+2]['insn'].bytes
        else:
            if 'bytes' in common_objs.disassembled_firmware[ldr_target+2]:
                next_ins_bytes = \
                    common_objs.disassembled_firmware[ldr_target+2]['bytes']
            else:
                logging.warning(
                    'No instruction or bytes found!!! '
                    + 'See target referenced by instruction at address: '
                    + hex(ins_address)
                )
                return consts.ERROR_INVALID_INSTRUCTION
                
        # If the next "instruction" contains only 2 bytes, then we only need
        #  to concatenate them to existing data bytes.
        if len(next_ins_bytes) == 2:
            data_bytes += next_ins_bytes
        # However, if next instruction contains 4 bytes, then we need to use two,
        #  and push the other two to next address.
        elif len(next_ins_bytes) == 4:
            data_bytes += next_ins_bytes[0:2]
            common_objs.disassembled_firmware[ldr_target+4]['bytes'] = \
                next_ins_bytes[2:]
        else:
            logging.error(
                'Required 4 bytes not found. '
                + 'See ldr target referenced from: '
                + hex(ins_address)
            )
            return consts.ERROR_INVALID_INSTRUCTION
        
        # Update firmware object.
        common_objs.disassembled_firmware[ldr_target+2]['insn'] = None
        
        return data_bytes
        
    def check_valid_pc_ldr(self, insn):
        if (insn.id not in [ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRH,
                ARM_INS_LDRSB, ARM_INS_LDRSH]):
            return False
            
        operands = insn.operands
        if len(operands) < 2:
            logging.error(
                'Unexpected number of operands for ldr instruction at address: '
                + hex(ins_address)
            )
            return False
            
        if operands[1].value.reg != ARM_REG_PC:
            return False
            
        return True
            
    def get_ldr_target_data_bytes(self, ldr_target):
        if common_objs.disassembled_firmware[ldr_target]['insn'] != None:
            data_bytes = common_objs.disassembled_firmware[ldr_target]['insn'].bytes 
        else:
            if 'bytes' in common_objs.disassembled_firmware[ldr_target]:
                data_bytes = common_objs.disassembled_firmware[ldr_target]['bytes']
            else:
                logging.warning(
                    'No instruction or bytes found!!! '
                    + 'See target referenced by instruction at address: '
                    + hex(ldr_target)
                )
                return consts.ERROR_INVALID_INSTRUCTION
        return data_bytes
                    
    def check_inline_address_instructions(self):
        logging.debug('Checking for presence of inline addresses.')
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        min_address = all_addresses[0]
        max_address = all_addresses[-1]
        for ins_address in common_objs.disassembled_firmware:
            if ins_address < common_objs.code_start_address:
                continue
            if ins_address in common_objs.errored_instructions:
                continue
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn == None:
                continue
            
            # If the instruction is not a valid LDR instruction, then don't bother.
            if self.check_valid_pc_ldr(insn) != True:
                continue
            if insn.id != ARM_INS_LDR:
                continue
            curr_pc_value = self.reg_eval.get_mem_access_pc_value(ins_address)
                
            # Target address is PC + offset.
            operands = insn.operands
            ldr_target = curr_pc_value + operands[1].mem.disp
            ordered_bytes = common_objs.disassembled_firmware[ldr_target]['data']

            # If it's an LDR instruction, then the bytes themselves may 
            #  represent an address within the instructions.
            if ((ordered_bytes >= min_address) and (ordered_bytes <= max_address)):
                inline_address = ordered_bytes
                if inline_address in common_objs.disassembled_firmware:
                    logging.debug(
                        'Marking inline address as data '
                        + hex(inline_address)
                    )
                    common_objs.disassembled_firmware[inline_address]['is_data'] = True
                    common_objs.disassembled_firmware[inline_address]['insn'] = None
                    
    # ------------------------------------------------------
    def check_valid_branches(self, disassembled_fw):
        logging.debug(
            'Checking basic branches and creating backlinks.'
        )
        for ins_address in disassembled_fw:
            if disassembled_fw[ins_address]['is_data'] == True:
                continue
                
            opcode_id = disassembled_fw[ins_address]['insn'].id
            
            # Check whether the opcode is for a branch instruction at all.
            if opcode_id not in [ARM_INS_BL, ARM_INS_B]:
                continue
                
            # Create backlink.
            disassembled_fw = self.create_backlink(
                disassembled_fw,
                ins_address
            )
        return disassembled_fw
                
    def create_backlink(self, disassembled_fw, ins_address):
        if disassembled_fw[ins_address]['is_data'] == True:
            return disassembled_fw
            
        insn = disassembled_fw[ins_address]['insn']
            
        branch_address = insn.operands[0].value.imm
        
        # The address should already be present in our disassembled firmware.
        if branch_address not in disassembled_fw:
            # If the address is not in disassembled firmware, add it to
            #  potential errors.
            if ins_address not in common_objs.errored_instructions:
                common_objs.errored_instructions.append(ins_address)
            return disassembled_fw
        # If the target is data, then it is an invalid branch.
        if (disassembled_fw[branch_address]['is_data'] == True):
            if ins_address not in common_objs.errored_instructions:
                common_objs.errored_instructions.append(ins_address)
            return disassembled_fw
        
        # Add back-links to disassembled firmware object. 
        if 'xref_from' not in disassembled_fw[branch_address]:
            disassembled_fw[branch_address]['xref_from'] = []
        if ins_address not in disassembled_fw[branch_address]['xref_from']:
            disassembled_fw[branch_address]['xref_from'].append(ins_address)
            
        return disassembled_fw
        
    def mark_last_instruction(self, disassembled_fw):
        last_good_instruction = common_objs.code_start_address
        for ins_address in disassembled_fw:
            if ins_address < common_objs.code_start_address:
                continue
            if disassembled_fw[ins_address]['is_data'] == True:
                continue
            if ins_address in common_objs.errored_instructions:
                continue
            if disassembled_fw[ins_address]['insn'].id == 0:
                continue
            if disassembled_fw[ins_address]['insn'].id == ARM_INS_NOP:
                continue
            if (disassembled_fw[ins_address]['insn'].id 
                    in [ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW]):
                operands = disassembled_fw[ins_address]['insn'].operands
                if len(operands) == 2:
                    if operands[0].value.reg == operands[1].value.reg:
                        continue
            disassembled_fw[ins_address]['last_insn_address'] = \
                last_good_instruction
            last_good_instruction = ins_address
        return disassembled_fw