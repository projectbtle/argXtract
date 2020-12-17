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
from argxtract.resources.vendor.nordic_ant import consts as nordic_consts


class VendorChipsetAnalyser:
    def __init__(self):
        self.embedded_softdevice = False
        
    def test_binary_against_vendor(self):
        logging.info('Checking whether firmware matches Nordic profile.')
        
        # Check for presence of embedded softdevice code.
        # Do this only if file is large enough.
        file_size_in_bytes = os.stat(common_paths.path_to_fw).st_size
        
        # A very small file wouldn't be firmware.
        if file_size_in_bytes < 0xC0:
            return None
            
        min_softdevice_size = 1024 * 53
        if (file_size_in_bytes > min_softdevice_size):
            self.check_for_embedded_softdevice()
        
        if self.embedded_softdevice != True:
            # Make sure firmware is Nordic.
            is_nordic = self.test_nordic()
            if is_nordic == False:
                logging.warning(
                    'The provided firmware file does not follow the pattern '
                    + 'for Nordic ANT firmware.'
                )
                return None
            else:
                logging.debug(
                    'File appears to match pattern for Nordic ANT.'
                )
        
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
            
        # Get relevant SVC set.
        self.get_svc_set()
        common_objs.vendor_svc_set = self.vendor_svc_set
        return True
        
    def test_nordic(self):
        if self.embedded_softdevice == True:
            return True
        if common_objs.vector_table_size == 0xC0:
            self.pre_sdk13 = True
            debug_msg = 'Vector table size matches sdk <13'
            logging.info(debug_msg)
            return True
        elif common_objs.vector_table_size == 0x0200:
            self.pre_sdk13 = False
            debug_msg = 'Vector table size matches sdk >=13'
            logging.info(debug_msg)
            return True
        else:
            return False
        
    def check_for_embedded_softdevice(self):
        logging.info('Checking for embedded softdevice.')
        with open(common_paths.path_to_fw, 'rb') as f:
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
            
        # Also get application code base.
        self.get_app_base_from_softdevice() 
        
        # If softdevice is embedded, the AVT will be further down.
        logging.info('Recomputing AVT due to embedded softdevice.')
        fw_disassembler = FirmwareDisassembler()
        fw_disassembler.analyse_vector_table(common_objs.app_code_base)

    def get_app_base_from_softdevice(self):
        # TODO: Implement
        pass
        
    def get_svc_set(self):
        self.vendor_svc_set = {
                    "sd_ant_stack_reset": "0xC0",
                    "sd_ant_event_get": "0xc1",
                    "sd_ant_channel_assign": "0xc2",
                    "sd_ant_channel_unassign": "0xc3",
                    "sd_ant_channel_open_with_offset": "0xc4",
                    "sd_ant_channel_close": "0xc5",
                    "sd_ant_rx_scan_mode_start": "0xc6",
                    "sd_ant_broadcast_message_tx": "0xc7",
                    "sd_ant_acknowledge_message_tx": "0xc8",
                    "sd_ant_burst_handler_request": "0xc9",
                    "sd_ant_pending_transmit_clear": "0xca",
                    "sd_ant_transfer_stop": "0xcb",
                    "sd_ant_network_address_set": "0xcc",
                    "sd_ant_channel_radio_freq_set": "0xcd",
                    "sd_ant_channel_radio_freq_get": "0xce",
                    "sd_ant_channel_radio_tx_power_set": "0xcf",
                    "sd_ant_prox_search_set": "0xd0",
                    "sd_ant_channel_period_set": "0xd1",
                    "sd_ant_channel_period_get": "0xd2",
                    "sd_ant_channel_id_set": "0xd3",
                    "sd_ant_channel_id_get": "0xd4",
                    "sd_ant_search_waveform_set": "0xd5",
                    "sd_ant_channel_search_timeout_set": "0xd6",
                    "sd_ant_search_channel_priority_set": "0xd7",
                    "sd_ant_active_search_sharing_cycles_set": "0xd8",
                    "sd_ant_active_search_sharing_cycles_get": "0xd9",
                    "sd_ant_channel_low_priority_rx_search_timeout_set": "0xda",
                    "sd_ant_adv_burst_config_set": "0xdb",
                    "sd_ant_adv_burst_config_get": "0xdc",
                    "sd_ant_lib_config_set": "0xdd",
                    "sd_ant_lib_config_clear": "0xde",
                    "sd_ant_lib_config_get": "0xdf",
                    "sd_ant_id_list_add": "0xe0",
                    "sd_ant_id_list_config": "0xe1",
                    "sd_ant_auto_freq_hop_table_set": "0xe2",
                    "sd_ant_event_filtering_set": "0xe3",
                    "sd_ant_event_filtering_get": "0xe4",
                    "sd_ant_active": "0xe5",
                    "sd_ant_channel_in_progress": "0xe6",
                    "sd_ant_channel_status_get": "0xe7",
                    "sd_ant_pending_transmit": "0xe8",
                    "sd_ant_cw_test_mode_init": "0xe9",
                    "sd_ant_cw_test_mode": "0xea",
                    "sd_ant_version_get": "0xeb",
                    "sd_ant_capabilities_get": "0xec",
                    "sd_ant_burst_handler_wait_flag_enable": "0xed",
                    "sd_ant_burst_handler_wait_flag_disable": "0xee",
                    "sd_ant_sdu_mask_set": "0xef",
                    "sd_ant_sdu_mask_get": "0xf0",
                    "sd_ant_sdu_mask_config": "0xf1",
                    "sd_ant_crypto_channel_enable": "0xf2",
                    "sd_ant_crypto_key_set": "0xf3",
                    "sd_ant_crypto_info_set": "0xf4",
                    "sd_ant_crypto_info_get": "0xf5",
                    "sd_ant_rfactive_notification_config_set": "0xf6",
                    "sd_ant_rfactive_notification_config_get": "0xf7",
                    "sd_ant_coex_config_set": "0xf8",
                    "sd_ant_coex_config_get": "0xf9",
                    "sd_ant_enable": "0xfa",
                    "SVC_ANT_RESERVED1": "0xfb",
                    "SVC_ANT_RESERVED2": "0xfc",
                    "sd_ant_extended0": "0xfd",
                    "SVC_ANT_EXTENDED1": "0xfe",
                    "SVC_ANT_EXTENDED2": "0xff"
                }
            
    
    # ==============================================================
    def generate_output_metadata(self):
        metadata = {
            "embedded_softdevice": self.embedded_softdevice
        }
        return metadata
        
    def reset(self):
        self.embedded_softdevice = False