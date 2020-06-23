import os
import sys
import logging
from svcxtract.core import consts
from svcxtract.common import paths as common_paths
from svcxtract.common import objects as common_objs


class ChipsetAnalyser:
    def __init__(self):
        pass
        
    def initialise(self, vendor):
        self.vendor_analyser = None
        
        self.path_to_vendors = os.path.join(
            common_paths.resources_path,
            'vendor'
        )

        vendor_dirs = next(os.walk(self.path_to_vendors))[1]
        if vendor == None:
            if len(vendor_dirs) > 1:
                logging.critical(
                    'Multiple possibilities for vendor '
                    + '(or multiple sub-directories in vendor directory). '
                    + 'Specify a vendor manually. Use --help flag for details.'
                )
                common_objs.vendor = None
                return
            else:
                vendor = vendor_dirs[0]
        else:
            if vendor not in vendor_dirs:
                logging.critical(
                    'Chipset specific files not available for vendor: '
                    + vendor
                )
                common_objs.vendor = None
                return

        # Load vendor-specific module.
        vendor_analyser_path = os.path.join(
            self.path_to_vendors,
            vendor
        )
        try:
            sys.path.append(os.path.abspath(vendor_analyser_path))
            from chipset_analyser import VendorChipsetAnalyser
            self.vendor_analyser = VendorChipsetAnalyser()
        except Exception as e:
            logging.critical(
                'Unable to import vendor-specific chipset analyser. '
                'Error: '
                + str(e)
            )
            common_objs.vendor = None
            return
            
        common_objs.vendor = vendor
        
    def test_chipset_against_vendor(self, path_to_fw):
        # Perform tests.
        is_vendor = self.vendor_analyser.test_chipset(path_to_fw)
        if is_vendor == True:
            return True
        else:
            return False

    def generate_output_metadata(self):
        metadata_obj = self.vendor_analyser.generate_output_metadata()
        return metadata_obj  

    def reset(self):
        if self.vendor_analyser != None:
            self.vendor_analyser.reset()
            
    def get_svc_num(self, svc_name):
        self.vendor_analyser.get_svc_num(svc_name)
    