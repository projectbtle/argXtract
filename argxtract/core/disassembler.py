import os
import sys
import struct
import logging

from capstone import *
from capstone.arm import *
from collections import Counter

from argxtract.common import paths as common_paths
from argxtract.core import utils
from argxtract.core import consts
from argxtract.common import objects as common_objs

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
# Turn on SKIPDATA mode - this is needed!
md.skipdata = True
md.detail = True


class FirmwareDisassembler:
    def __init__(self):
        self.arm_switch8 = None
        
    def estimate_app_code_base(self):
        logging.info('Estimating app code base.')
        
        # Get AVT
        self.read_vector_table()

        """ This is quite a hacky way of doing things, but with stripped 
            binaries, we have very little to go on. 
            We first get the addresses for interrupt handlers from vector table. 
            We then look for all branch statements with <self> as target address.
            We then compare the last 3 hex values of addresses, and get matches.
            App code base is then 
                (vector_table_entry_address - self_targeting_branch_address)
        """
        
        # Initialise app code base.
        app_code_base = 0x00000000
        
        # Populate interrupt handler addresses.
        interrupt_handlers = []
        for key in common_objs.application_vector_table:
            if key in ['initial_sp', 'reset']:
                continue
            address = hex(common_objs.application_vector_table[key])
            interrupt_handlers.append(address)
        
        # Populate self-targeting branch addresses.
        self_targeting_branches = self.populate_self_targeting_branches()
        
        if len(self_targeting_branches) == 0:
            logging.debug(
                'No self-targeting branches. App code base cannot be determined.'
            )

        # Check the self-targeting branches against interrupt handlers.
        # Hopefully there isn't more than one match.
        possible_code_bases = []
        for interrupt_handler in interrupt_handlers:
            for self_targeting_branch in self_targeting_branches:
                logging.debug(
                    'Testing interrupt handler ' 
                    + interrupt_handler
                    + ' against self targeting branch at '
                    + self_targeting_branch
                )
                if (self_targeting_branch.replace('0x', ''))[-3:] in interrupt_handler:
                    logging.debug('Match found!')
                    app_code_base = \
                        int(interrupt_handler, 16) - int(self_targeting_branch, 16)
                    if app_code_base < 0: continue
                    possible_code_bases.append(app_code_base)
        
        if len(possible_code_bases) > 1:
            logging.warning('More than one possibility for app code base.')
            c = Counter(possible_code_bases)
            app_code_base, _ = c.most_common()[0]
            
        common_objs.app_code_base = app_code_base
        common_objs.disassembly_start_address = common_objs.app_code_base
        common_objs.code_start_address = common_objs.app_code_base + (4*15)
        # Populate self-targeting branches, with app code base offset)
        for self_targeting_branch in self_targeting_branches:
            common_objs.self_targeting_branches.append(
                int(self_targeting_branch, 16) + 
                common_objs.app_code_base
            )
        
        debug_msg = 'App code base estimated as: ' + hex(app_code_base)
        logging.info(debug_msg)
        
    def read_vector_table(self, base=0):
        application_vector_table = {}
        image_file = open(common_paths.path_to_fw, 'rb')
        for avt_entry in consts.AVT.keys():
            image_file.seek(0)
            image_file.seek(base+consts.AVT[avt_entry])
            vector_table_entry = struct.unpack('<I', image_file.read(4))[0]
            if vector_table_entry == 0x00000000:
                continue
            if vector_table_entry%2 == 1:
                vector_table_entry -= 1
            application_vector_table[avt_entry] = vector_table_entry
        
        common_objs.application_vector_table = application_vector_table
        debug_msg = 'Partial Application Vector Table:'
        for avt_entry in application_vector_table:
            debug_msg += '\n\t\t\t\t\t\t\t\t' \
                         + avt_entry \
                         + ': ' \
                         + hex(application_vector_table[avt_entry]) 
        logging.info(debug_msg)
    
    def populate_self_targeting_branches(self):
        self_targeting_branches = []
        self.create_disassembled_object()
        for ins_address in common_objs.disassembled_firmware:
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
                
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn == None: continue
            opcode_id = insn.id
            
            # Check whether the opcode is for a branch instruction at all.
            # Basic branches are easy.
            if opcode_id in [ARM_INS_BL, ARM_INS_B]:
                target_address_int = insn.operands[0].value.imm
                target_address = hex(target_address_int)
                if target_address_int == ins_address:
                    self_targeting_branches.append(target_address)
            # BX Rx is more complicated.
            # This would be in the form of LDR Rx, [PC, offset], 
            #  followed by BX Rx
            if opcode_id == ARM_INS_BX:
                branch_register = insn.operands[0].value.reg
                # LDR normally doesn't load to LR?
                if branch_register == ARM_REG_LR:
                    continue
                # Firstly, we assume that such functions don't have
                #  a large number of instructions. One or two at most.
                # The LDR is assumed to be the immediately preceding
                #  instruction.
                if (ins_address-2) not in common_objs.disassembled_firmware:
                    continue
                if self.check_valid_pc_ldr(ins_address-2) != True:
                    continue
                prev_insn = common_objs.disassembled_firmware[ins_address-2]['insn']
                if prev_insn.id != ARM_INS_LDR:
                    continue
                curr_pc_value = self.get_mem_access_pc_value(ins_address-2)
                ldr_target = curr_pc_value + prev_insn.operands[1].mem.disp
                if ldr_target not in common_objs.disassembled_firmware:
                    if ins_address not in common_objs.errored_instructions:
                        common_objs.errored_instructions.append(ins_address)
                        logging.trace(
                            'LDR target ('
                            + hex(ldr_target)
                            + ') is not present in disassembled firmware '
                            + 'for LDR call at '
                            + hex(ins_address)
                            + '. Adding to errored instructions.'
                        )
                    continue
                if (abs(ldr_target-ins_address) > 4096):
                    if ins_address not in common_objs.errored_instructions:
                        common_objs.errored_instructions.append(ins_address)
                        logging.trace(
                            'LDR target ('
                            + hex(ldr_target)
                            + ') is at an offset greater than 4096 '
                            + 'for LDR call at '
                            + hex(ins_address)
                            + '. Adding to errored instructions.'
                        )
                    continue
                data_bytes = self.get_ldr_target_data_bytes(ldr_target)
                if len(data_bytes) < 4:
                    data_bytes = self.get_data_from_next_instruction(
                        ins_address-2,
                        ldr_target,
                        data_bytes
                    )
                    if data_bytes == consts.ERROR_INVALID_INSTRUCTION:
                        if ins_address not in common_objs.errored_instructions:
                            common_objs.errored_instructions.append(ins_address)
                            logging.trace(
                                'Unable to get LDR bytes '
                                + 'for LDR call at '
                                + hex(ins_address)
                                + '. Adding to errored instructions.'
                            )
                        continue
                ordered_bytes = struct.unpack('<I', data_bytes)[0]
                target_branch = ordered_bytes - 1 # Thumb mode needs -1
                if target_branch == (ins_address-2):
                    self_targeting_branches.append(hex(target_branch))
        self_targeting_branches.sort()       
        common_objs.disassembled_firmware = {}
        return self_targeting_branches
        
    def create_disassembled_object(self, store=True):
        disassembled_fw = self.disassemble_fw()

        # This is for the initial fw checks.
        if store != True:
            return disassembled_fw
            
        common_objs.disassembled_firmware = disassembled_fw
        disassembled_fw = None
        
    def identify_inline_data(self):   
        logging.info('Identifying inline data.')
        
        # Add dummy keys, to handle Capstone issues.
        disassembled_firmware_with_dummy_keys = self.add_dummy_keys(
            common_objs.disassembled_firmware
        )
        
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
        
        # Trace
        trace_msg = 'Final instructions: \n'
        for address in common_objs.disassembled_firmware:
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                if 'data' not in common_objs.disassembled_firmware[address]:
                    continue
                data = common_objs.disassembled_firmware[address]['data']
                trace_msg += '\t\t\t\t\t\t\t\t0x%x:\t%s\t%s\t%s\n' %(address,
                                            hex(data),
                                            'data',
                                            '')
            else:
                insn = common_objs.disassembled_firmware[address]['insn']
                bytes = insn.bytes
                bytes = ''.join('{:02x}'.format(x) for x in bytes)
                trace_msg += '\t\t\t\t0x%x:\t%s\t%s\t%s\n' %(address,
                                            bytes,
                                            insn.mnemonic,
                                            insn.op_str)
        logging.trace(trace_msg)
        
    def annotate_links(self):
        # Create backlinks.
        common_objs.disassembled_firmware = self.check_valid_branches(
            common_objs.disassembled_firmware
        )
        
        # Mark out last known instruction.
        common_objs.disassembled_firmware = self.mark_last_instruction(
            common_objs.disassembled_firmware
        )
        
        # Estimate architecture.
        self.test_arm_arch()
        
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
            trace_msg += '\t\t\t\t\t\t\t\t0x%x:\t%s\t%s\t%s\n' %(instruction.address,
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

        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        min_address = all_addresses[-1]
        
        # Read in data from the Reset Handler.
        self.identify_data_segment_via_reset_handler()

        self.handle_potential_byte_misinterpretation_errors()
        
        self.identify_arm_switch8()
        
        ins_address = common_objs.code_start_address - 2
        while ins_address < min_address:
            ins_address = utils.get_next_address(
                all_addresses,
                ins_address
            )
            if ins_address == None: break

            if ins_address in common_objs.errored_instructions:
                continue
  
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn == None:
                continue
   
            # If ID is 0, then it may mean inline data.
            if insn.id == ARM_INS_INVALID:
                if ('byte' in insn.mnemonic):
                    common_objs.errored_instructions.append(ins_address)
                    logging.trace(
                        '"byte" in mnemonic at '
                        + hex(ins_address)
                        + '. Adding to errored instructions.'
                    )
                    continue
                common_objs.disassembled_firmware[ins_address]['is_data'] = True
                continue
                
            # If it's a BL to ARM_SWITCH8:
            if insn.id == ARM_INS_BL:
                target_address_int = insn.operands[0].value.imm
                if target_address_int == self.arm_switch8:
                    # Skip next few instructions.
                    lr_value = ins_address+4
                    switch_table_len_byte = utils.get_firmware_bytes(lr_value, 1)
                    end_index = int(switch_table_len_byte, 16)
                    post_skip_instruction_address = lr_value + end_index + 2
                    if post_skip_instruction_address%2 == 1: 
                        post_skip_instruction_address += 1
                    logging.debug(
                        'Call to ARM_Switch8 at '
                        + hex(ins_address)
                        + '. Skipping next few instructions to '
                        + hex(post_skip_instruction_address)
                    )
                    switch8_address = lr_value
                    while switch8_address < post_skip_instruction_address:
                        common_objs.disassembled_firmware[switch8_address]['is_data'] = True
                        switch8_address = utils.get_next_address(
                            all_addresses,
                            switch8_address
                        )
                    # 2 will be added in the loop.
                    ins_address = post_skip_instruction_address - 2
                    continue
            
            # Table branch indices.
            if insn.id in [ARM_INS_TBB, ARM_INS_TBH]:
                if ins_address not in common_objs.table_branches:
                    common_objs.table_branches[ins_address] = {}
                index_register = insn.operands[0].value.mem.index
                common_objs.table_branches[ins_address]['comparison_register'] = \
                    index_register
                    
                pc_address = ins_address + 4
                address = ins_address
                comparison_address = address
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
                    comparison_address = address
                    break
                    
                cbranch = comparison_address
                cbranch_condition = None
                while cbranch < ins_address:
                    cbranch += 2
                    if common_objs.disassembled_firmware[cbranch]['is_data'] == True:
                        continue
                    if common_objs.disassembled_firmware[cbranch]['insn'] == None:
                        continue
                    branch_insn = common_objs.disassembled_firmware[cbranch]['insn']
                    if branch_insn.id != ARM_INS_B:
                        continue
                    cbranch_condition = branch_insn.cc
                        
                common_objs.table_branches[ins_address]['comparison_value'] = \
                    comp_value
                common_objs.table_branches[ins_address]['comparison_address'] = \
                    comparison_address
                common_objs.table_branches[ins_address]['branch_address'] = \
                    cbranch
                common_objs.table_branches[ins_address]['branch_condition'] = \
                    cbranch_condition
                    
                if cbranch_condition == ARM_CC_HS:
                    comp_value -= 1
                    
                num_entries = (comp_value + 1)
                if insn.id == ARM_INS_TBB:
                    mul_factor = 1
                if insn.id == ARM_INS_TBH:
                    mul_factor = 2
                size_table = num_entries * mul_factor
                common_objs.table_branches[ins_address]['size_table'] = size_table
                
                table_branch_max = pc_address + size_table
                if insn.id == ARM_INS_TBB:
                    if (table_branch_max%2 == 1):
                        table_byte = utils.get_firmware_bytes(table_branch_max, 1)
                        if table_byte == '00':
                            table_branch_max += 1
                        else:
                            logging.error('Unhandled TBB')
                            table_branch_max += 1
                
                common_objs.table_branches[ins_address]['table_branch_max'] = \
                    table_branch_max
                    
                logging.debug(
                    'Skip TBB/TBH at '
                    + hex(ins_address)
                    + ' to '
                    + hex(table_branch_max)
                )
                    
                # Get all possible addresses.
                table_branch_addresses = []
                for i in range(comp_value+1):
                    index_address = pc_address + (mul_factor*i)
                    value = utils.get_firmware_bytes(
                        index_address, 
                        num_bytes=mul_factor
                    )
                    value = int(value, 16)
                    branch_address = pc_address + (2*value)
                    table_branch_addresses.append(branch_address)
                common_objs.table_branches[ins_address]['table_branch_addresses'] = \
                    table_branch_addresses
                
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
            if ((self.check_valid_pc_ldr(ins_address) != True) and (insn.id != ARM_INS_ADR)):
                continue
            curr_pc_value = self.get_mem_access_pc_value(ins_address)
            operands = insn.operands
            
            # If ADR is loading to registers other than R0-R2,
            #  then don't use it for inline data identification?
            # Hack to reduce FPs.
            if (insn.id == ARM_INS_ADR):
                if operands[0].value.reg not in [ARM_REG_R0, ARM_REG_R1, ARM_REG_R2]:
                    continue
            
            # Target address is PC + offset.
            ldr_target = curr_pc_value + operands[1].mem.disp
            if insn.id == ARM_INS_ADR:
                ldr_target = curr_pc_value + operands[1].value.imm
            if ldr_target not in common_objs.disassembled_firmware:
                if ins_address not in common_objs.errored_instructions:
                    common_objs.errored_instructions.append(ins_address)
                    logging.trace(
                        'LDR/ADR target ('
                        + hex(ldr_target)
                        + ') is not present is disassembled firmware '
                        + 'for call at '
                        + hex(ins_address)
                        + '. Adding to errored instructions.'
                    )
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
                    logging.trace(
                        'Unable to get data bytes for load instruction at '
                        + hex(ins_address)
                        + '. Adding to errored instructions.'
                    )
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
            if (ldr_target+2) in common_objs.disassembled_firmware:
                common_objs.disassembled_firmware[ldr_target+2]['is_data'] = True
            common_objs.disassembled_firmware[ldr_target]['insn'] = None  
            
            if ((insn.id == ARM_INS_LDR) or (insn.id == ARM_INS_ADR)):
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
                            logging.trace(
                                'Unable to load data bytes for LDR call at '
                                + hex(ins_address)
                                + '. Adding to errored instructions.'
                            )
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

    def handle_potential_byte_misinterpretation_errors(self):
        for ins_address in common_objs.disassembled_firmware:
            if ins_address < common_objs.code_start_address:
                continue
                
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn == None: continue
            
            # If ID is 0, then it may mean inline data.
            # But it may also be Capstone incorrectly disassembling a word.
            if insn.id == ARM_INS_INVALID:
                if ('byte' in insn.mnemonic):
                    byte_misinterpretation = \
                        self.handle_byte_misinterpretation(ins_address, insn)
                    if byte_misinterpretation == True:
                        continue
                
    def handle_byte_misinterpretation(self, ins_address, insn):
        logging.debug('Handling potential incorrect .byte at ' + hex(ins_address))
        if ((ins_address + 2) in common_objs.disassembled_firmware):
            next_adr = common_objs.disassembled_firmware[ins_address+2]
            next_insn = next_adr['insn']
            if next_insn.id != ARM_INS_INVALID:
                next_insn_bytes = next_insn.bytes
                if len(next_insn_bytes) != 4:
                    return False
                next_insn = md.disasm(
                    next_insn_bytes[0:2], 
                    ins_address+2
                )
                for code_start_insn in next_insn:
                    common_objs.disassembled_firmware[ins_address+2]['insn'] = \
                        code_start_insn
                    common_objs.disassembled_firmware[ins_address+2]['is_data'] = False
                    break
      
                next_insn = md.disasm(
                    next_insn_bytes[2:4], 
                    ins_address+4
                )
                for code_start_insn in next_insn:
                    common_objs.disassembled_firmware[ins_address+4]['insn'] = \
                        code_start_insn
                    common_objs.disassembled_firmware[ins_address+4]['is_data'] = False
                    break
                return True
        return False
    
    def identify_arm_switch8(self):
        logging.debug('Checking for __ARM_common_switch8')
        arm_switch8 = None
        for ins_address in common_objs.disassembled_firmware:
            if ins_address in common_objs.errored_instructions:
                continue
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
                
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn == None: continue
            
            is_potential_arm_switch8 = False
            if insn.id == ARM_INS_PUSH:
                operands = insn.operands
                if len(operands) == 2:
                    if ((operands[0].value.reg == ARM_REG_R4) 
                            and (operands[1].value.reg == ARM_REG_R5)):
                        is_potential_arm_switch8 = True
            if is_potential_arm_switch8 != True:
                continue
            if ((ins_address+2) not in common_objs.disassembled_firmware):
                is_potential_arm_switch8 = False
                continue
            next_insn = common_objs.disassembled_firmware[ins_address+2]['insn']
            if next_insn == None:
                is_potential_arm_switch8 = False
                continue
            if next_insn.id not in [ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW]:
                is_potential_arm_switch8 = False
                continue
            next_operands = next_insn.operands
            if next_operands[0].value.reg != ARM_REG_R4:
                is_potential_arm_switch8 = False
                continue
            if next_operands[1].value.reg != ARM_REG_LR:
                is_potential_arm_switch8 = False
                continue
            if is_potential_arm_switch8 == True:
                arm_switch8 = ins_address
                break
        if arm_switch8 == None: return
        logging.info('ARM switch8 identified at ' + hex(arm_switch8))
        self.arm_switch8 = arm_switch8
        common_objs.replace_functions[arm_switch8] = {
            'type': consts.SWITCH8
        }
        
    def identify_data_segment_via_reset_handler(self):
        reset_handler_address = common_objs.application_vector_table['reset']
        address = reset_handler_address - 2
        max_address = address + 30
        data_start_firmware_address = ''
        data_start_real_address = ''
        while address < max_address:
            address += 2
            insn = common_objs.disassembled_firmware[address]['insn']
            if insn == None:
                continue
            
            # If a self-targeting branch is encountered, we've probably
            #  come to another interrupt handler.
            if insn.id == ARM_INS_B:
                if insn.cc == ARM_CC_AL:
                    branch_target = insn.operands[0].value.imm
                    if branch_target < common_objs.code_start_address:
                        logging.trace(
                            'Branch target ('
                            + hex(branch_target)
                            + ') is not less than code start address '
                            + 'for call at '
                            + hex(ins_address)
                            + '. Adding to errored instructions.'
                        )
                        common_objs.errored_instructions.append(address)
                        continue
                    if branch_target == address:
                        break
                        
            # If there's inline data, we've probably come to the end.
            if insn.id == ARM_INS_INVALID:
                if ('byte' in insn.mnemonic):
                    common_objs.errored_instructions.append(address)
                    logging.trace(
                        '"byte" in mnemonic at '
                        + hex(address)
                        + '. Adding to errored instructions.'
                    )
                    continue
                common_objs.disassembled_firmware[address]['is_data'] = True
                break
            if common_objs.disassembled_firmware[address]['is_data'] == True:
                break
                
            if self.check_valid_pc_ldr(address) != True:
                continue
                
            if insn.id == ARM_INS_LDR:
                curr_pc_value = self.get_mem_access_pc_value(address)
                
                # Target address is PC + offset.
                operands = insn.operands
                ldr_target = curr_pc_value + operands[1].mem.disp
                ldr_value = utils.get_firmware_bytes(ldr_target, 4)
                ldr_value = int(ldr_value, 16)
                common_objs.disassembled_firmware[ldr_target]['is_data'] = True
                if (ldr_target+2) in common_objs.disassembled_firmware:
                    common_objs.disassembled_firmware[ldr_target+2]['is_data'] = True
                common_objs.disassembled_firmware[ldr_target]['data'] = ldr_value
                if ldr_value in common_objs.disassembled_firmware:
                    if ldr_value < common_objs.code_start_address:
                        continue
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
                else:
                    # The LDR from address in firmware precedes LDR from RAM.
                    if data_start_firmware_address == '':
                        continue
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
        all_addresses.sort()
        last_address = all_addresses[-1]
        if data_start_firmware_address >= last_address:
            return
        data_region = {}
        fw_address = data_start_firmware_address
        real_address = data_start_real_address
        while fw_address <= last_address:
            if real_address % 4 == 0:
                data_region_value = \
                    utils.get_firmware_bytes(
                        fw_address, 
                        4,
                        endian='big'
                    )
                data_region[real_address] = data_region_value
                common_objs.disassembled_firmware[fw_address]['data'] = \
                    int(data_region_value, 16)
            common_objs.disassembled_firmware[fw_address]['is_data'] = True
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
            if (ldr_target+4) not in common_objs.disassembled_firmware:
                logging.error(
                    'Required 4 bytes not found. '
                    + 'See ldr target referenced from: '
                    + hex(ins_address)
                )
                return consts.ERROR_INVALID_INSTRUCTION
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
        
    def check_valid_pc_ldr(self, ins_address):
        insn = common_objs.disassembled_firmware[ins_address]['insn']
        if insn == None: return False
        
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
            
        # If it's not PC-relative address, return false.
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
        ins_address = common_objs.code_start_address - 2
        while ins_address < min_address:
            ins_address = utils.get_next_address(
                all_addresses,
                ins_address
            )
            if ins_address == None: break
            
            if ins_address in common_objs.errored_instructions:
                continue
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
            insn = common_objs.disassembled_firmware[ins_address]['insn']
            if insn == None:
                continue
                    
            # If the instruction is not a valid LDR instruction, then don't bother.
            if self.check_valid_pc_ldr(ins_address) != True:
                continue
            if insn.id != ARM_INS_LDR:
                continue
            curr_pc_value = self.get_mem_access_pc_value(ins_address)

            # Target address is PC + offset.
            operands = insn.operands
            ldr_target = curr_pc_value + operands[1].mem.disp
            ordered_bytes = common_objs.disassembled_firmware[ldr_target]['data']

            # If it's an LDR instruction, then the bytes themselves may 
            #  represent an address within the instructions.
            if ((ordered_bytes >= min_address) and (ordered_bytes <= max_address)):
                is_target_address_data = False
                ldr_target_register = insn.operands[0].value.reg
                test_address = ins_address
                for i in range(5):
                    test_address = utils.get_next_address(
                        all_addresses,
                        test_address
                    )
                    test_insn = common_objs.disassembled_firmware[test_address]['insn']
                    if test_insn == None:
                        continue
                    if test_insn.id == 0:
                        continue
                    # If the value loaded in register gets used in 
                    #  register-relative LDR, then the address is marked 
                    #  as containing data.
                    if test_insn.id == ARM_INS_LDR:
                        if test_insn.operands[1].value.reg == ldr_target_register:
                            is_target_address_data = True
                            break
                    # If the value loaded in register gets overwritten, 
                    #  don't continue.
                    if len(test_insn.operands) > 0:
                        if test_insn.operands[0].value.reg == ldr_target_register:
                            break
                if is_target_address_data != True:
                    continue
                inline_address = ordered_bytes
                if inline_address in common_objs.disassembled_firmware:
                    logging.debug(
                        'Marking inline address as data '
                        + hex(inline_address)
                        + ' as called from '
                        + hex(ins_address)
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
                logging.trace(
                    'Branch target ('
                    + hex(branch_address)
                    + ') is not present is disassembled firmware '
                    + 'for call at '
                    + hex(ins_address)
                    + '. Adding to errored instructions.'
                )
            return disassembled_fw
        # If the target is data, then it is an invalid branch.
        if (disassembled_fw[branch_address]['is_data'] == True):
            if ins_address not in common_objs.errored_instructions:
                common_objs.errored_instructions.append(ins_address)
                logging.trace(
                    'Branch target ('
                    + hex(branch_address)
                    + ') is data '
                    + 'for call at '
                    + hex(ins_address)
                    + '. Adding to errored instructions.'
                )
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
                    # Don't mark as data, because NOPs are sometimes used 
                    #  within functions.
                    if operands[0].value.reg == operands[1].value.reg:
                        continue
            disassembled_fw[ins_address]['last_insn_address'] = \
                last_good_instruction
            last_good_instruction = ins_address
        return disassembled_fw
        
    def test_arm_arch(self):
        arch7m_ins = [ARM_INS_UDIV, ARM_INS_TBB, ARM_INS_TBH]
        for ins_address in common_objs.disassembled_firmware:
            if ins_address < common_objs.code_start_address:
                continue
            if common_objs.disassembled_firmware[ins_address]['is_data'] == True:
                continue
            if common_objs.disassembled_firmware[ins_address]['insn'] == None:
                continue
            if ins_address in common_objs.errored_instructions:
                continue
            if common_objs.disassembled_firmware[ins_address]['insn'].id == 0:
                continue
            if common_objs.disassembled_firmware[ins_address]['insn'].id in arch7m_ins:
                common_objs.arm_arch = consts.ARMv7M
                
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