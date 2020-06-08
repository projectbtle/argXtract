import os
import sys
import json
import hashlib
import logging
import argparse
from svcxtract.core.analyser import FirmwareAnalyser

class ExtractaSVC:
    def __init__(self):
        self.vendor = None
        self.core_file_list = []
        self.loglevel = logging.INFO
        logging.getLogger().setLevel(self.loglevel)
        self.set_args()
        self.check_args()
        
    def set_args(self):
        self.argparser = argparse.ArgumentParser(
            description = 'ExtractaSVC enables testing Nordic firmware '
                          + 'files to enumerate services and characteristics, '
                          + ' and identify characteristic protection levels.',
            epilog = 'Note that this tool has only been '
                     + 'tested with Python 3.7+. '
                     + 'It will not work with lower versions.\n'
        )
        group = self.argparser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            '-d',
            '--directory',
            type = str,
            action = 'store',
            help = 'directory containing firmware files to be analysed. '
                   + 'Provide absolute path to directory as argument.'
        )
        group.add_argument(
            '-f',
            '--file',
            type = str,
            action = 'store',
            help = 'individual firmware file to be analysed.'
        )
        group.add_argument(
            '-l',
            '--list',
            type = str,
            action = 'store',
            help = 'text file containing absolute paths of '
                   + 'firmware files to be analysed.'
        )
        self.argparser.add_argument(
            '-c',
            '--console',
            type = str,
            choices = ['c', 'e', 'w', 'i', 'd', 't'],
            action = 'store',
            nargs = '?',
            help = 'console log level. '
                   + 'One of c (critical), '
                   + 'e (error), '
                   + 'w (warning), '
                   + 'i (info), '
                   + 'd (debug), '
                   + 't (trace).'
        )
        self.argparser.add_argument(
            '-v',
            '--vendor',
            type = str,
            action = 'store',
            help = 'the vendor/chipset to test against. '
                    + 'Vendor-specific files must be added to the repo.'
        )
        
    def check_args(self):
        args = self.argparser.parse_args()
        if args.directory:
            fw_directory = args.directory
            if (not(os.path.isdir(fw_directory))):
                logging.critical(
                    'Firmware folder does not exist!'
                )
                sys.exit(0)
            for root, dir, fw_files in os.walk(fw_directory):
                for fw_file in fw_files:
                    filepath = os.path.join(root, fw_file)
                    if (not(os.path.isfile(filepath))):
                        logging.error(
                            'File does not exist: '
                            + filepath
                        )
                        continue
                    if filepath not in self.core_file_list:
                        self.core_file_list.append(filepath)
        elif args.list:
            filelist = args.list
            if (not(os.path.isfile(args.list))):
                logging.critical(
                    'Firmware list file does not exist! '
                    + filelist
                )
                sys.exit(0)
            fw_files = []
            with open(filelist) as f:
                fw_files = f.read().splitlines()
            for fw_file in fw_files:
                if (not(os.path.isfile(fw_file))):
                    logging.error(
                        'File does not exist: '
                        + fw_file
                    )
                    continue
                if fw_file not in self.core_file_list:
                    self.core_file_list.append(fw_file)
        elif args.file:
            filepath = args.file
            if (not(os.path.isfile(args.file))):
                logging.critical(
                    'Firmware file does not exist! '
                    + filepath
                )
                sys.exit(0)
            if filepath not in self.core_file_list:
                self.core_file_list.append(filepath)

        # Check if log level is specified.
        if args.console:
            if args.console == 'c':
                self.loglevel = logging.CRITICAL
            elif args.console == 'e':
                self.loglevel = logging.ERROR
            elif args.console == 'w':
                self.loglevel = logging.WARNING
            elif args.console == 'i':
                self.loglevel = logging.INFO
            elif args.console == 'd':
                self.loglevel = logging.DEBUG
            elif args.console == 't':
                self.loglevel = logging.TRACE
            logging.getLogger().setLevel(self.loglevel)
        
        if args.vendor:
            self.vendor = args.vendor
            
    def start_analysis(self):
        # Banner.
        print(
            '\n==================================\n'
            + 'ExtractaSVC\n'
            + '==================================\n'
        )
        
        logging.info(
            str(len(self.core_file_list))
            + ' firmware files to analyse.'
        )
        output_tracker = open('fw_to_output.txt', 'a')
        firmware_analyser = FirmwareAnalyser(self.vendor)
        for fw_file in self.core_file_list:
            #try:
            # Get hash of file bytes.
            filebytes = open(fw_file, 'rb').read()
            m = hashlib.sha256(filebytes)
            # Don't waste resources by keeping file bytes in memory.
            filebytes = None
            # Get digest value.
            digest = m.hexdigest()
            outputfilename = './output/' + digest + '.json'
            # Get analysis output.
            output = firmware_analyser.analyse_firmware(fw_file)
            # Write to file.
            with open(outputfilename, 'w') as f: 
                json.dump(output, f, indent=4)
            # Keep track of digest and associated filepath.
            output_tracker.write(fw_file + ',' + digest + '\n')

if __name__ == '__main__':
    analysable_instance = ExtractaSVC()
    analysable_instance.start_analysis()