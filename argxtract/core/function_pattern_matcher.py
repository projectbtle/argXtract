import os
import sys
import copy
import json
import logging
from capstone import *
from capstone.arm import *
from argxtract.common import paths as common_paths
from argxtract.core import utils
from argxtract.core import consts
from argxtract.common import objects as common_objs

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
# Turn on SKIPDATA mode - this is needed!
md.skipdata = True
md.detail = True


class FunctionPatternMatcher:
    def __init__(self):
        all_addresses = list(common_objs.disassembled_firmware.keys())
        all_addresses.sort()
        self.all_addresses = all_addresses
        
    def match_vendor_functions(self):
        logging.info('Performing vendor function pattern matching.')
        