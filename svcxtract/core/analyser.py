import os
import sys
import json
import numpy
import timeit
import logging
from svcxtract.core import utils
from svcxtract.core import consts
from svcxtract.common import paths as common_paths
from svcxtract.common import objects as common_objs
from svcxtract.core.svc_analyser import SvcAnalyser
from svcxtract.core.chipset_analyser import ChipsetAnalyser
from svcxtract.core.disassembler import FirmwareDisassembler
from svcxtract.core.function_evaluator import FunctionEvaluator
from svcxtract.core.register_evaluator import RegisterEvaluator


class FirmwareAnalyser:
    def __init__(self, vendor, max_time, max_call_depth, loglevel, 
                    null_handling, process_id):
        common_objs.max_time = max_time
        common_objs.max_call_depth = max_call_depth
        common_objs.null_value_handling = null_handling
        logging.getLogger().setLevel(loglevel)
        self.set_paths(process_id)
        
        # First things first, run vendor tests.
        self.chipset_analyser = ChipsetAnalyser()
        self.chipset_analyser.initialise(vendor)
        if common_objs.vendor == None:
            return None
        
    def analyse_firmware(self, path_to_fw):
        # Start with clean slate.
        self.reset()
        
        # Start timer.
        start_time = timeit.default_timer()
        
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
        
        # Set path, once file is confirmed to exist.
        common_paths.path_to_fw = path_to_fw
        
        # Test for compiler type.
        utils.test_gcc_vs_other()
        
        # Run vendor-specific tests and find out the chipset/vendor.
        # This function will also set chipset-specific variables, 
        #  such as app code base, etc.
        vendor_match = self.chipset_analyser.test_chipset_against_vendor(
            path_to_fw
        )
        if vendor_match != True:
            logging.critical(
                'Unable to match firmware to vendor.'
            )
            return None
        
        # Set paths for SVC.
        self.svc_analyser.set_vendor_paths()
        
        # Disassemble fw.
        self.disassembler.create_disassembled_obj()
        
        # Identify function blocks, possible memset, and blacklist.
        self.function_evaluator.perform_function_block_analysis()
        
        # Create SVC object.
        self.svc_analyser.create_svc_object()
        # If there are no SVC calls, then we can't proceed with analysis.
        if len(common_objs.svc_calls.keys()) == 0:
            logging.critical(
                'The provided firmware file appears to have '
                + 'no SVC calls. '
                + 'It cannot be analysed using this tool.'
            )
            return None
        
        # Now do individual SVC calls of interest.
        output_object = self.svc_analyser.process_svc_chains()

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
        final_output['svcs'] = output_object['svcs']
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
        self.svc_analyser = None
        self.register_evaluator = None
        
        self.disassembler = FirmwareDisassembler()
        self.function_evaluator = FunctionEvaluator()
        self.svc_analyser = SvcAnalyser()
        self.register_evaluator = RegisterEvaluator()
        
        # Reset paths.
        common_paths.path_to_fw = ''
        
        # Reset objects.
        
        # Variables.
        common_objs.compiler = consts.COMPILER_GCC
        # Firmware breakdown.
        common_objs.app_code_base = 0x00000000
        common_objs.disassembly_start_address = 0x00000000
        common_objs.code_start_address = 0x00000000
        common_objs.flash_length = 0x00000000
        common_objs.ram_base = 0x00000000
        common_objs.ram_length = 0x00000000
        common_objs.vector_table_size = 0
        common_objs.application_vector_table = {}
        common_objs.svc_set = {}
        common_objs.core_bytes = None
        common_objs.disassembled_firmware = {}
        common_objs.errored_instructions = []
        common_objs.function_blocks = {}
        common_objs.memory_access_functions = {}
        common_objs.blacklisted_functions = []
        common_objs.svc_calls = {}
        # Tracing objects.
        common_objs.svc_chains = []
        common_objs.potential_start_points = []
        # Chipset-specific reset.
        self.chipset_analyser.reset()
        
        
