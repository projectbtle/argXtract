# Chipset Analysis Code

The file `argxtract/resources/vendor/<vendor>/chipset_analyser.py` must have a class `VendorChipsetAnalyser`, with the following methods:
* `test_binary_against_vendor`
* `generate_output_metadata`
* `reset`
* `get_svc_num`

The expected functionality for each of these methods is described in this page.

## Functionality of `test_binary_against_vendor`
This function takes as input the path to the firmware file that is under test. It must test the file to determine whether it matches the expected pattern. How this is done will depend on the vendor/chipset and is left up to you. The only requirement is that this function must set certain common values in `argxtract.common.objects` that will be used by other components of the tool:
* `app_code_base` - Application code base. Chipset-specific.
* `disassembly_start_address` - Normally the same as `app_code_base`. However, if the firmware is self-contained, i.e., contains the platform _and_ application code, then the `disassembly_start_address` will be `0x00000000`.
* `vector_table_size` - Chipset-specific. 
* `application_vector_table` - ARM applications typically have the vector table at the beginning of the binary. However, in the case of self-contained firmware, the vector table will be positioned further down within the file. This variable is a dictionary object with a structure as specified in `argxtract.core.consts`. It must contain the values for the initial Stack Pointer and the reset handler at a minimum.
* `code_start_address` - This is equal to `vector_table_size` + `app_code_base`.
* `ram_base` - Base address of RAM.
* `ram_length` - RAM size.
* `svc_set` - A dictionary object with `<svc_name>:<svc_number>` pairs. The `<svc_name>` can be anything as long as it is used consistently within the code.

## Functionality of `generate_output_metadata`
If any vendor-specific metadata is to be included in output file, include it here. Otherwise, return None or empty object.

## Functionality of `reset`
If vendor-specific variables were set, which are to be set per-file, then they must be reset each time. If there are no such variables set, then leave this as an empty function.

## Functionality of `get_svc_num`
If there isn't an exact mapping available for the chipset and SVC set, then you might want some sort of majority vote-based method to assign the most likely SVC number (this should normally not be needed, in which case just use an empty function).


## Minimal example:
```
from argxtract.common import objects as common_objs


class VendorChipsetAnalyser:
    def __init__(self):
        pass
        
    def test_binary_against_vendor(self, path_to_firmware_file):
        <vendor-specific tests>
        
        if tests_failed:
            return False
        
        common_objs.vector_table_size = 0xc0
        common_objs.code_start_address = common_objs.app_code_base + common_objs.vector_table_size
        
        common_objs.vendor_svc_set = {
            "svc_name1": 0xa0,
            "svc_name2": 0xa1
        }
        
        return True
        
    def generate_output_metadata:
        return {}
        
    def reset:
        return
        
    def get_svc_num:
        return
```