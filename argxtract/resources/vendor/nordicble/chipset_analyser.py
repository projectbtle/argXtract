import os
import sys
import json
import struct
import logging
from capstone.arm import *
from collections import Counter
from argxtract.common import paths as common_paths
from argxtract.core import utils
from argxtract.core import consts
from argxtract.common import objects as common_objs
from argxtract.core.disassembler import FirmwareDisassembler
from argxtract.resources.vendor.nordicble import consts as nordic_consts


class VendorChipsetAnalyser:
    def __init__(self):
        self.pre_sdk13 = None
        self.embedded_softdevice = False
        self.softdevice_version = None
        self.sdk_version = None
        self.estimated = True
        self.soc_family = None
        
    def test_chipset(self, path_to_fw):
        logging.info('Checking whether firmware matches Nordic profile.')
        
        # Check for presence of embedded softdevice code.
        # Do this only if file is large enough.
        file_size_in_bytes = os.stat(path_to_fw).st_size
        
        # A very small file wouldn't be firmware.
        if file_size_in_bytes < 0xC0:
            return None
            
        min_softdevice_size = 1024 * 49
        if (file_size_in_bytes > min_softdevice_size):
            self.check_for_embedded_softdevice(
                path_to_fw
            )
        
        if self.embedded_softdevice != True:
            # Make sure firmware is Nordic.
            is_nordic = self.test_nordic(path_to_fw)
            if is_nordic == False:
                logging.warning(
                    'The provided firmware file does not follow the pattern '
                    + 'for Nordic firmware.'
                )
                return None
            else:
                logging.debug(
                    'File appears to match pattern for Nordic.'
                )
            
            # Get application base.
            self.get_app_base()
            
            # Estimate softdevice version.
            self.estimate_sd_sdk()
            
            # If app code base is still 0x00000000,
            #  then we can't really proceed?
            if common_objs.app_code_base == 0x00000000:
                logging.warning(
                    'SoftDevice/SDK cannot be estimated.'
                )
                return None
                
            # Get flash length, etc.
            self.estimate_flash_ram()
        
        if self.softdevice_version == None:
            logging.warning('Could not estimate a SoftDevice.')
            return None
            
        if self.softdevice_version[0] == '2':
            logging.warning('ANT-only SoftDevice.')
            return None
        
        # Define disassembler start address.
        if self.embedded_softdevice == True:
            common_objs.disassembly_start_address = 0x00000000
        else:
            common_objs.disassembly_start_address = common_objs.app_code_base
            
        # Define code start address.
        common_objs.code_start_address = common_objs.vector_table_size \
                                + common_objs.app_code_base
        logging.info(
            'Code start address is: '
            + hex(common_objs.code_start_address)
        )
        
        # Set chipset family.
        self.set_soc_family()
            
        # Get relevant SVC set.
        self.get_svc_set()
        return True
        
    def test_nordic(self, path_to_fw):
        if self.embedded_softdevice == True:
            return True
        image_file = open(path_to_fw, 'rb')
        is_pre13_sdk = self.test_for_nordic_vector_table(image_file, 0xBC)
        is_post13_sdk = self.test_for_nordic_vector_table(image_file, 0x01FC)
        image_file = None
        if is_pre13_sdk == True:
            common_objs.vector_table_size = 0xC0
            self.pre_sdk13 = True
            debug_msg = 'Vector table size matches sdk <13'
            logging.info(debug_msg)
            return True
        elif is_post13_sdk == True:
            common_objs.vector_table_size = 0x0200
            self.pre_sdk13 = False
            debug_msg = 'Vector table size matches sdk >=13'
            logging.info(debug_msg)
            return True
        else:
            return False
            
    def test_for_nordic_vector_table(self, image_file, offset):
        image_file.seek(0)
        image_file.seek(offset)
        end_vt = image_file.read(4).hex()
        # There should be at least some separation between Vector Table
        #  and start of code?
        if ((end_vt != '00000000') and (end_vt != 'ffffffff')):
            return False
        # Code won't start with 0's or F's?
        start_code = image_file.read(4).hex()
        if ((start_code == '00000000') or (start_code == 'ffffffff')):
            return False
            
        # Do we want more stringent checks?
        # Maybe ensure that most of the next lines do have code?
        zero_counter = 0
        for i in range(5):
            image_file.seek(0)
            image_file.seek(offset + 4 + (i*0x10))
            next_code = image_file.read(4).hex()
            if (next_code == '00000000'):
                zero_counter += 1
        if zero_counter > 2:
            return False
        return True
        
    def check_for_embedded_softdevice(self, image_file):
        logging.info('Checking for embedded softdevice.')
        with open(image_file, 'rb') as f:
            firmware_contents = f.read().hex()
            
        softdevice_dir = os.path.join(
            common_paths.resources_path,
            'vendor',
            'nordic',
            'softdevices'
        )
        
        file_list = []
        for root, dirs, files in os.walk(softdevice_dir):
            for file in files:
                file_list.append((file, os.path.join(root, file)))
             
        softdevice_match = None             
        for one_file in file_list:
            file = one_file[0]
            softdevice_file = one_file[1]
            with open(softdevice_file, 'rb') as f1:
                softdevice_contents = f1.read().hex()
                if softdevice_contents in firmware_contents:
                    softdevice_match = file.lower()
                    break
                        
        if (softdevice_match == None):
            return
        
        self.embedded_softdevice = True
        self.estimated = False
        debug_msg = 'Softdevice embedded within firmware:\n'
        debug_msg += '\t\t\t\t' + softdevice_match
        logging.info(debug_msg)

        # We can also set softdevice, SDK, app base at this point.
        self.estimate_sd_sdk_from_softdevice(softdevice_match)
        
        # Set vector table size.
        int_sdk = int(self.sdk_version.split('.')[0])
        if int_sdk < 13:
            common_objs.vector_table_size = 0xC0
        else:
            common_objs.vector_table_size = 0x0200
            
        # Also get application code base.
        self.get_app_base_from_softdevice() 
        
        # If softdevice is embedded, the AVT will be further down.
        logging.info('Recomputing AVT due to embedded softdevice.')
        utils.analyse_vector_table(image_file, common_objs.app_code_base)
        
    def estimate_sd_sdk_from_softdevice(self, softdevice_match):
        softdevice = None
        sd_split = softdevice_match.split('_')
        
        for element in sd_split:
            if len(element) != 4:
                continue
            if element[0] != 's':
                continue
            if softdevice != None:
                logging.debug('More than one possible value for Softdevice?')
                continue                
            softdevice = element
            
        logging.info('Softdevice is: ' + softdevice)
        self.softdevice_version = softdevice
        
        # SDK can only be estimated. 
        sdk_version = softdevice_match.split('sdk_')[1]
        sdk_version = sdk_version.split('__')[0]
        self.sdk_version = sdk_version
        logging.info(
            'SDK is possibly: '
            + str(sdk_version)
        )
        
    def get_app_base_from_softdevice(self):
        bases = nordic_consts.APP_CODE_BASE_PER_SDK_SD
        matching_obj = \
            bases[self.sdk_version][self.softdevice_version]
        app_code_base = matching_obj['app_base']
        app_code_base = int(app_code_base, 16)
        common_objs.app_code_base = app_code_base
        logging.info(
            'App code base is: '
            + hex(app_code_base)
        )
        flash_length = matching_obj['flash_length']
        flash_length = int(flash_length, 16)
        common_objs.flash_length = flash_length
        debug_msg = 'App code base is: ' \
                    + hex(app_code_base) \
                    + ' and flash length is: ' \
                    + hex(flash_length)
        ram_base = matching_obj['ram_base']
        ram_base = int(ram_base, 16)
        common_objs.ram_base = ram_base
        ram_length = matching_obj['ram_length']
        ram_length = int(ram_length, 16)
        common_objs.ram_length = ram_length
        debug_msg += '\n\t\t\t\tRAM base is: ' \
                    + hex(ram_base) \
                    + ' and RAM length is: ' \
                    + hex(ram_length)
        logging.info(debug_msg)
        
    def get_app_base(self):
        """Get APP_CODE_BASE using SD/SDK or the Application Vector Table."""

        # If Softdevice was present within code, then app base is simple.
        if self.embedded_softdevice == True:
            return
            
        # This is quite a hacky way of doing things, but with stripped 
        #  binaries, we have very little to go on.
        # We first get the NMI Handler address from vector table.
        # We then look for all branch statements with <self> as target 
        #  address.
        # We then compare the last 3 hex values of addresses, to see
        #  which match.
        
        # Initialise app code base.
        app_code_base = 0x00000000
        
        # Error handlers.
        interrupt_handlers = []
        for key in common_objs.application_vector_table:
            if key in ['initial_sp', 'reset']:
                continue
            address = hex(common_objs.application_vector_table[key])
            interrupt_handlers.append(address)
        
        # Self-targeting branches.
        self_targeting_branches = []
        fw_disassembler = FirmwareDisassembler()
        disassembled = fw_disassembler.create_disassembled_obj(store=False)
        for ins_address in disassembled:
            if disassembled[ins_address]['is_data'] == True:
                continue
                
            insn = disassembled[ins_address]['insn']
            opcode_id = insn.id
            
            # Check whether the opcode is for a branch instruction at all.
            if opcode_id not in [ARM_INS_BL, ARM_INS_B]:
                continue
            
            target_address_int = insn.operands[0].value.imm
            target_address = hex(target_address_int)
            if target_address_int == ins_address:
                self_targeting_branches.append(target_address)
        disassembled = None
        
        if len(self_targeting_branches) == 0:
            logging.debug(
                'No self-targeting branches. App code base cannot be determined.'
            )

        possible_code_bases = []
        # Check the self-targeting branches against NMI.
        # Hopefully there isn't more than one match.
        for interrupt_handler in interrupt_handlers:
            for self_targeting_branch in self_targeting_branches:
                if (self_targeting_branch.replace('0x', ''))[-3:] in interrupt_handler:
                    app_code_base = \
                        int(interrupt_handler, 16) - int(self_targeting_branch, 16)
                    if app_code_base not in possible_code_bases:
                        possible_code_bases.append(app_code_base)
        
        if len(possible_code_bases) > 1:
            logging.error('More than one possibility for app code base.')
            app_code_base = 0x00000000
            
        common_objs.app_code_base = app_code_base
        if app_code_base == 0x00000000:
            debug_msg = 'Could not estimate app code base.'
        else:
            debug_msg = 'App code base estimated as: ' + hex(app_code_base)
        logging.info(debug_msg)

    def estimate_sd_sdk(self):
        if common_objs.app_code_base == 0x00000000:
            logging.info(
                'Could not estimate softdevice/SDK due to '
                + '0x00000000 app_code_base.'
            )
            return
            
        if self.embedded_softdevice == True:
            return

        if common_objs.app_code_base not in nordic_consts.APP_CODE_BASE:
            return
        sd_object = nordic_consts.APP_CODE_BASE[common_objs.app_code_base]
        potential_softdevices = list(sd_object.keys())
        if len(potential_softdevices) == 1:
            self.softdevice_version = potential_softdevices[0]
            logging.info(
                'Single possibility for softdevice: '
                + str(self.softdevice_version)
            )
            if len(sd_object[self.softdevice_version]) == 1:
                sdk_version = sd_object[self.softdevice_version][0]
                self.sdk_version = sdk_version
                logging.info(
                    'Single possibility for SDK: '
                    + str(sdk_version)
                )
            else:
                sdk_candidates = sd_object[self.softdevice_version]
                sdk_candidates.sort(reverse=True)
                sdk_version = sdk_candidates[0]
                if (('alpha' in sdk_version) or ('beta' in sdk_version)):
                    sdk_version = sdk_candidates[1]
                self.sdk_version = sdk_version
                logging.info(
                    'Multiple SDK possibilities. Estimated SDK: '
                    + str(sdk_version)
                )
            return
        
        candidates = {}
        sdk_candidates = {}
        for potential_softdevice in potential_softdevices:
            for sdk in sd_object[potential_softdevice]:
                cleaned_version = sdk.replace('v','').replace('V','')
                cleaned_version = cleaned_version.split('_')[0]
                cleaned_version = cleaned_version.split('.')[0]
                sdk_version = float(cleaned_version)
                if self.pre_sdk13 == True:
                    if sdk_version < 13:
                        if sdk not in sdk_candidates:
                            sdk_candidates[sdk] = []
                        if potential_softdevice not in sdk_candidates[sdk]:
                            sdk_candidates[sdk].append(potential_softdevice)
                        if potential_softdevice not in candidates:
                            candidates[potential_softdevice] = []
                        if sdk not in candidates[potential_softdevice]:
                            candidates[potential_softdevice].append(sdk)
                elif self.pre_sdk13 == False:
                    if sdk_version >= 13:
                        if sdk not in sdk_candidates:
                            sdk_candidates[sdk] = []
                        if potential_softdevice not in sdk_candidates[sdk]:
                            sdk_candidates[sdk].append(potential_softdevice)
                        if potential_softdevice not in candidates:
                            candidates[potential_softdevice] = []
                        if sdk not in candidates[potential_softdevice]:
                            candidates[potential_softdevice].append(sdk)
        list_candidates = list(candidates.keys())
        list_sdk_candidates = list(sdk_candidates.keys())
        if len(list_candidates) != 1:
            # If we don't get a unique softdevice, then pick the one with 
            #  newest SDK.
            list_sdk_candidates.sort(reverse=True)
            self.sdk_version = list_sdk_candidates[0]
            possible_softdevices = sdk_candidates[self.sdk_version]
            possible_softdevices.sort(reverse=True)
            self.softdevice_version = possible_softdevices[0]
            logging.info(
                'Multiple possibilities for softdevice.\n'
                '\t\t\t\tAssuming latest SDK (this may cause inaccurate results): '
                + str(self.sdk_version) + '\n'
                '\t\t\t\tSoftdevice estimated to be: '
                + str(self.softdevice_version)
            )
        else: 
            self.softdevice_version = list_candidates[0]
            logging.info(
                'Softdevice estimated to be: '
                + str(self.softdevice_version)
            )
            if len(candidates[self.softdevice_version]) == 1:
                sdk_version = candidates[self.softdevice_version][0]
                self.sdk_version = sdk_version
                logging.info(
                    'SDK estimated to be: '
                    + str(sdk_version)
                )
                self.estimated = False
            else:
                sorted_sdk = candidates[self.softdevice_version]
                sorted_sdk.sort(reverse=True)
                sdk_version = sorted_sdk[0]
                self.sdk_version = sdk_version
                logging.info(
                    'Multiple possibilities for SDK.\n'
                    '\t\t\t\tSDK estimated to be: '
                    + str(sdk_version)
                )
        return
        
    def estimate_flash_ram(self):
        bases = nordic_consts.APP_CODE_BASE_PER_SDK_SD
        matching_obj = \
            bases[self.sdk_version][self.softdevice_version]
        flash_length = matching_obj['flash_length']
        flash_length = int(flash_length, 16)
        common_objs.flash_length = flash_length
        debug_msg = 'Flash length is: ' \
                    + hex(flash_length)
        ram_base = matching_obj['ram_base']
        ram_base = int(ram_base, 16)
        common_objs.ram_base = ram_base
        ram_length = matching_obj['ram_length']
        ram_length = int(ram_length, 16)
        common_objs.ram_length = ram_length
        debug_msg += '\n\t\t\t\tRAM base is: ' \
                    + hex(ram_base) \
                    + ' and RAM length is: ' \
                    + hex(ram_length)
        logging.info(debug_msg)
    
    def get_svc_set(self):
        if self.softdevice_version == None:
            logging.debug(
                'Could not estimate SVC due to unknown softdevice version.'
            )
            return
        if self.sdk_version == None:
            self.estimate_svc_set()
            return
            
        logging.info(
            'Using SVC set corresponding to SDK: '
            + str(self.sdk_version)
            + ' and Softdevice: '
            + str(self.softdevice_version)
        )
        common_objs.svc_set = self.get_svc_set_from_database(
            self.sdk_version,
            self.softdevice_version
        )
            
    def estimate_svc_set(self):
        if common_objs.app_code_base == 0x00000000:
            logging.debug(
                'Could not estimate SVC due to 0x00000000 app code base.'
            )
            return
        logging.debug(
            'Cannot estimate SVC accurately due to unknown SDK. '
            + 'Attempting approximation.'
        )
        possible_sdks = \
            nordic_consts.APP_CODE_BASE[common_objs.app_code_base][self.softdevice_version]
            
        possible_svc_set = {}
        sdk_estimate = None
        all_match = True
        for possible_sdk in possible_sdks:
            if possible_sdk not in nordic_consts.NORDIC_SVC_NUMS:
                continue
            if self.softdevice_version not in nordic_consts.NORDIC_SVC_NUMS[possible_sdk]:
                continue
            if possible_svc_set == {}:
                possible_svc_set = self.get_svc_set_from_database(
                    possible_sdk,
                    self.softdevice_version
                )
                sdk_estimate = possible_sdk
            else:
                compare_svc_set = self.get_svc_set_from_database(
                    possible_sdk,
                    self.softdevice_version
                )
                if compare_svc_set != possible_svc_set:
                    all_match = False
                    break
        if all_match == False:
            logging.info(
                'Multiple possibilities for SVC set. '
                + 'Unable to determine a single set.'
            )
            return
            
        logging.info(
            'Using SVC set corresponding to SDK: '
            + str(sdk_estimate)
            + ' and Softdevice: '
            + str(self.softdevice_version)
        )
        common_objs.svc_set = possible_svc_set
            
    def get_svc_set_from_database(self, sdk, softdevice):
        default_obj = {}
        if sdk in nordic_consts.NORDIC_SVC_NUMS:
            if softdevice in nordic_consts.NORDIC_SVC_NUMS[sdk]:
                svc_obj = nordic_consts.NORDIC_SVC_NUMS[sdk][softdevice]
                for svc_group in svc_obj:
                    for svc_name in svc_obj[svc_group]:
                        default_obj[svc_name] = svc_obj[svc_group][svc_name]
        return default_obj

    def set_soc_family(self):
        if ((int(self.softdevice_version[2]) <= 3) 
                and (self.softdevice_version[3] == '0')):
            self.soc_family = nordic_consts.SOC_NRF51
        else:
            self.soc_family = nordic_consts.SOC_NRF52
        logging.info(
            'SoC family set to: '
            + self.soc_family
        )
        
    # =============================================================
    def get_svc_num(self, svc_name):
        candidates = []
        for sdk in nordic_consts.NORDIC_SVC_NUMS:
            # If incorrect SDK version, continue.
            sdk_version = float(sdk.split('.')[0])
            if self.pre_sdk13 == True:
                if sdk_version >= 13:
                    continue
            elif self.pre_sdk13 == False:
                if sdk_version < 13:
                    continue
                    
            # If incorrect softdevice version, continue.
            for sd in nordic_consts.NORDIC_SVC_NUMS[sdk]:
                if self.softdevice_version != None:
                    if sd != self.softdevice_version:
                        continue
                     
                for svc_group in nordic_consts.NORDIC_SVC_NUMS[sdk][sd]:
                    if svc_name in nordic_consts.NORDIC_SVC_NUMS[sdk][sd][svc_group]:
                        candidate = \
                            nordic_consts.NORDIC_SVC_NUMS[sdk][sd][svc_group][svc_name]
                        candidates.append(candidate)
                        
        # If all candidates are the same value, then it's straightforward.
        if len(list(set(candidates))) == 1:
            return candidate[0]
            
        # If not, return most frequent.
        candidates_by_freq = [item for items, c in 
                                    Counter(candidates).most_common()
                                      for item in [items] * c] 
        return candidates_by_freq[0]
        
    # ==============================================================
    def generate_output_metadata(self):
        metadata = {
            'compiler': common_objs.compiler,
            'app_vector_table_size': hex(common_objs.vector_table_size),
            'is_pre_sdk13': self.pre_sdk13,
            'embedded_softdevice': self.embedded_softdevice,
            'app_code_base': hex(common_objs.app_code_base),
            'flash_length': hex(common_objs.flash_length),
            'ram_base': hex(common_objs.ram_base),
            'ram_length': hex(common_objs.ram_length),
            'softdevice_version': self.softdevice_version,
            'sdk_version': self.sdk_version,
            'soc_family': self.soc_family,
            'is_estimated_data': self.estimated
        }
        return metadata
        
    def reset(self):
        self.pre_sdk13 = None
        self.embedded_softdevice = False
        self.softdevice_version = None
        self.sdk_version = None
        self.estimated = True
        self.soc_family = None