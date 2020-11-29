# Chipset Analysis Code

The file `argxtract/resources/vendor/<vendor>/chipset_analyser.py` must have a class `VendorChipsetAnalyser`, with the following methods:
* `test_binary_against_vendor`
* `generate_output_metadata`
* `reset`
* `get_svc_num` (only for SVC analysis mode)

The expected functionality for each of these methods is described in this page.

## Functionality of `test_binary_against_vendor`
This function takes as input the path to the firmware file that is under test, and checks the file to determine whether it matches the expected pattern. How this is done will depend on the vendor/chipset and is left up to you (optional). The only requirement is that, if the analysis mode is `s` (i.e., SVC), then the function must set the following in `argxtract.common.objects`:
* `svc_set` - A dictionary object with `<svc_name>:<svc_number>` pairs. The `<svc_name>` can be anything as long as it is used consistently within the code.

## Functionality of `generate_output_metadata`
If any vendor-specific metadata is to be included in output file, include it here. Otherwise, return object.

## Functionality of `reset`
If vendor-specific variables were set, which are to be set per-file, then they must be reset each time. If there are no such variables set, then leave this as an empty function.

## Functionality of `get_svc_num`
If there isn't an exact mapping available for the chipset and SVC set, then you might want some sort of majority vote-based method to assign the most likely SVC number (this should normally not be needed, in which case just use an empty function). Only relevant for SVC mode.


## Minimal example:
```
from argxtract.common import objects as common_objs


class VendorChipsetAnalyser:
    def __init__(self):
        pass
        
    def test_binary_against_vendor(self, path_to_firmware_file):
        <optional vendor-specific tests>
        
        if tests_failed:
            return False
        
        # The following is mandatory for SVC mode.
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
        # Only required for SVC analysis mode.
        return
```