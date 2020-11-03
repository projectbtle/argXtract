import os
import sys
import json
import numpy
import timeit
import logging
from argxtract.core import utils
from argxtract.core import consts
from argxtract.common import paths as common_paths
from argxtract.common import objects as common_objs
from argxtract.core.coi_processor import CoiProcessor
from argxtract.core.chipset_analyser import ChipsetAnalyser
from argxtract.core.disassembler import FirmwareDisassembler
from argxtract.core.function_evaluator import FunctionEvaluator
from argxtract.core.register_evaluator import RegisterEvaluator


class FirmwareAnalyser:
    def __init__(self, mode, vendor, max_time, max_call_depth, loglevel, 
                    null_handling, bypass, process_id):
        common_objs.mode = mode
        common_objs.max_time = max_time
        common_objs.max_call_depth = max_call_depth
        common_objs.null_value_handling = null_handling
        common_objs.bypass_all_conditional_checks = bypass
        
        logging.getLogger().setLevel(loglevel)
        self.set_paths(process_id)

        # First things first, run vendor tests.
        # These are NOT tests on the firmware file itself,
        #  but tests to initialise the vendor component.
        # Do not move or remove.
        self.chipset_analyser = ChipsetAnalyser()
        self.chipset_analyser.initialise(vendor)
        if common_objs.vendor == None:
            return None
        
        # Set vendor paths.
        common_paths.vendor_path = os.path.join(
            common_paths.resources_path,
            'vendor',
            common_objs.vendor
        )
        
    def analyse_firmware(self, path_to_fw):
        # Start with clean slate.
        self.reset()
        
        # Start timer.
        start_time = timeit.default_timer()
        
        """ Basic checks """
        logging.info(
            'Checking file: "'
            + path_to_fw
            + '".\n'
        )
        
        # Does file even exist?
        if (not (os.path.isfile(path_to_fw))):
            logging.critical(
                'File "'
                + path_to_fw
                + '" does not exist!'
            )
            return None
        
        file_size_in_bytes = os.stat(path_to_fw).st_size
        # A very small file wouldn't be firmware. 
        # ARM AVT itself is at least 60 bytes.
        if file_size_in_bytes < 0x3C:
            return None
        
        # Set path, once file is confirmed to exist.
        common_paths.path_to_fw = path_to_fw
        
        """ Step 1: Get app code base """
        # Get application code base.
        self.disassembler.estimate_app_code_base()
        
        # Run vendor-specific tests and set binary/chipset-specific variables.
        vendor_match = self.chipset_analyser.test_binary_against_vendor()
        if vendor_match != True:
            logging.critical(
                'Unable to match firmware to vendor.'
            )
            return None

        """ Step 2: Disassemble and annotate data and other pertinent info """
        # Disassemble firmware binary.
        self.disassembler.create_disassembled_object()
        
        # Mark out .data and inline data.
        self.disassembler.identify_inline_data()
        
        # Annotate firmware object with branch call/target information.
        self.disassembler.annotate_links()

        """ Step 3: Function block estimation and pattern matching """
        # Identify function blocks
        self.function_evaluator.estimate_function_blocks()
        
        # Identify denylisted blocks (that should not be considered when tracing).
        # Functions we shouldn't branch to.
        self.function_evaluator.populate_denylist()
        
        # Perform function pattern matching.
        self.function_evaluator.perform_function_pattern_matching()

        """ Step 4: Mark locations of COIs """
        # Create COI object.
        self.coi_processor.identify_coi_addresses()

        # If there are no calls to COIs, then we can't proceed with analysis.
        if len(common_objs.coi_addresses.keys()) == 0:
            logging.critical(
                'The provided firmware file appears to have '
                + 'no calls to COIs. '
                + 'It cannot be analysed using this tool.'
            )
            return None
        
        """ Step 5: Trace """
        # Now do individual calls of interest.
        output_object = self.coi_processor.process_coi_chains()

        """ Finalise. """
        final_output = self.add_metadata(output_object)
        serializable_output = self.convert_to_serializable(final_output)

        # Print time.
        stoptime = timeit.default_timer()
        runtime = stoptime - start_time
        logging.info('Finished analysing in ' + str(runtime) + ' seconds.')
        serializable_output['analysis_time'] = runtime
        
        return serializable_output
        
    def convert_to_serializable(self, object):
        new_object = {}
        for key in object:
            if type(object[key]) is dict:
                new_object[key] = self.convert_to_serializable(object[key])
            elif ((isinstance(object[key], numpy.int64)) 
                    or (isinstance(object[key], numpy.uint64))
                    or (isinstance(object[key], numpy.int8))
                    or (isinstance(object[key], numpy.uint8))
                    or (isinstance(object[key], numpy.int16))
                    or (isinstance(object[key], numpy.uint16))
                    or (isinstance(object[key], numpy.int32))
                    or (isinstance(object[key], numpy.uint32))):
                converted_value = \
                    getattr(object[key], "tolist", lambda: object[key])()                  
                new_object[key] = converted_value
            elif type(object[key]) is list:
                list_items = object[key]
                new_list = []
                for list_item in list_items:
                    if type(list_item) is dict:
                        new_list_item = self.convert_to_serializable(
                            list_item
                        )
                        new_list.append(new_list_item)
                    else:
                        new_list.append(list_item)
                new_object[key] = new_list
            else:
                new_object[key] = object[key]
        return new_object
    
    def add_metadata(self, output_object):
        final_output = {}
        final_output['filepath'] = common_paths.path_to_fw
        # Add chipset-specific metadata.
        chipset_metadata = self.chipset_analyser.generate_output_metadata()
        if ((chipset_metadata != {}) and (chipset_metadata != None)):
            final_output['metadata'] = chipset_metadata
        # Add output object.
        final_output['output'] = output_object['output']
        final_output['cois'] = output_object['cois']
        final_output['unhandled'] = output_object['unhandled']
        return final_output
        
    def set_paths(self, process_id):
        curr_path = os.path.dirname(os.path.realpath(__file__))
        base_path = os.path.abspath(
            os.path.join(curr_path, '..')
        )
        common_paths.base_path = base_path
        common_paths.core_path = os.path.abspath(
            os.path.join(base_path, 'core')
        )
        common_paths.resources_path = os.path.abspath(
            os.path.join(base_path, 'resources')
        )
        common_paths.tmp_path = os.path.abspath(
            os.path.join(base_path, '..', 'tmp', str(process_id))
        )
        if (not (os.path.isdir(common_paths.tmp_path))):
            os.mkdir(common_paths.tmp_path)
        
    def reset(self):
        self.disassembler = None
        self.function_evaluator = None
        self.coi_processor = None
        self.register_evaluator = None
        
        self.disassembler = FirmwareDisassembler()
        self.function_evaluator = FunctionEvaluator()
        self.coi_processor = CoiProcessor()
        self.register_evaluator = RegisterEvaluator()
        
        # Reset paths.
        common_paths.path_to_fw = ''
        
        # Reset variables.
        common_objs.arm_arch = consts.ARMv6M
        #> Firmware breakdown.
        common_objs.app_code_base = 0x00000000
        common_objs.disassembly_start_address = 0x00000000
        common_objs.code_start_address = 0x00000000
        common_objs.flash_length = 0x00000000
        common_objs.ram_base = 0x00000000
        common_objs.ram_length = 0x00000000
        common_objs.vector_table_size = 0
        common_objs.application_vector_table = {}
        common_objs.self_targeting_branches = []
        common_objs.vendor_svc_set = {}
        common_objs.core_bytes = None
        common_objs.disassembled_firmware = {}
        common_objs.data_region = {}
        common_objs.errored_instructions = []
        common_objs.function_blocks = {}
        common_objs.replace_functions = {}
        common_objs.denylisted_functions = []
        common_objs.coi_addresses = {}
        #> Tracing objects.
        common_objs.coi_chains = []
        common_objs.coi_function_blocks = []
        common_objs.potential_start_points = []
        #> Chipset-specific reset.
        self.chipset_analyser.reset()
        
    