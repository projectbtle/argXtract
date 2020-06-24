import os
import sys
import json
import hashlib
import logging
import argparse
from svcxtract.common import objects as common_objs
from svcxtract.core.analyser import FirmwareAnalyser
from multiprocessing import Process, JoinableQueue, active_children


class SVCXtract:
    def __init__(self):
        self.vendor = None
        self.processes = 1
        self.core_file_list = []
        self.loglevel = logging.INFO
        logging.getLogger().setLevel(self.loglevel)
        self.set_args()
        self.check_args()
        
    def set_args(self):
        self.argparser = argparse.ArgumentParser(
            description = 'SVCXtract enables testing Nordic firmware '
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
            '-t',
            '--time',
            type = int,
            action = 'store',
            help = 'maximum trace time per file in seconds.'
        )
        self.argparser.add_argument(
            '-m',
            '--max_call_depth',
            type = int,
            action = 'store',
            help = 'maximum call depth of a function to be included in trace.'
        )
        self.argparser.add_argument(
            '-v',
            '--vendor',
            type = str,
            action = 'store',
            help = 'the vendor/chipset to test against. '
                    + 'Vendor-specific files must be added to the repo.'
        )
        self.argparser.add_argument(
            '-p',
            '--processes',
            type = int,
            action = 'store',
            help = 'number of parallel processes ("threads") to use.'
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
            
        if args.time:
            if args.time > 0:
                common_objs.max_time = int(args.time)
                
        if args.max_call_depth:
            if args.max_call_depth > 0:
                common_objs.max_call_depth = args.max_call_depth
                
        if args.processes:
            if args.processes > 0:
                self.processes = args.processes
            
    def start_analysis(self):
        # Banner.
        print(
            '\n==================================\n'
            + 'SVCXtract\n'
            + '==================================\n'
        )
        
        logging.info(
            str(len(self.core_file_list))
            + ' firmware files to analyse.'
        )

        if self.processes == 1:
            self.execute_single_process()
        else:
            self.execute_multiple_processes()
            
    def execute_single_process(self):
        firmware_analyser = FirmwareAnalyser(self.vendor, self.loglevel)
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
            if output == None:
                continue
            # Write to file.
            with open(outputfilename, 'w') as f: 
                json.dump(output, f, indent=4)
                
    def execute_multiple_processes(self):
        # We don't want long messages in parallel threads.
        logging.getLogger().setLevel(logging.CRITICAL)
        
        length_fw_list = int(len(self.core_file_list)/self.processes)
        print(
            "Total number of FW files: " 
            + str(len(self.core_file_list)) 
            + "\nNumber of files per thread:"
            + str(length_fw_list)
        )
    
        #Create queues for sending jobs to worker threads and receiving results from them.
        process_send_queue = JoinableQueue()
        process_receive_queue = JoinableQueue() 
        
        num_processes = 0
        process_list = []
        
        #Create worker processes.
        for i in range(0, self.processes):
            workerx = SVCXtractWorker(self.vendor, self.loglevel)
            worker = Process(
                target=workerx.main,
                args=(
                    process_send_queue,
                    process_receive_queue,
                    num_processes
                )
            )
            worker.start()
            process_list.append(worker)
            num_processes+=1
            
        #Send jobs to worker processes.
        for fw_file in self.core_file_list:
            process_send_queue.put(fw_file)
            
        completed_apk_count = 0
        
        while True:
            #Get and process information sent by worker process.
            result = process_receive_queue.get()
            process_receive_queue.task_done()
            
            # Log, etc.
            filename = result.split(',')[0]
            print('Finished analysing ' + filename)
            
            #Check if any processes have become zombies.
            if len(active_children()) < self.processes:
                for p in process_list:
                    if not p.is_alive():
                        process_list.remove(p)
                        # Create replacement worker.
                        workerx = SVCXtractWorker(self.vendor, self.loglevel)
                        worker = Process(
                            target=workerx.main, 
                            args=(
                                process_send_queue,
                                process_receive_queue,
                                num_processes
                            )
                        )
                        worker.start()
                        process_list.append(worker)
                        num_processes+=1

            #Check if all APKs have been analysed.
            completed_apk_count+=1
            if completed_apk_count == len(self.core_file_list):
                break
                
        print("All done")
        # Tell child processes to stop
        for i in range(self.processes):
            process_send_queue.put('STOP')
            

class SVCXtractWorker:
    def __init__(self, vendor, loglevel):
        self.vendor = vendor
        self.loglevel = loglevel
        logging.getLogger().setLevel(loglevel)
        
    def main(self, in_queue, out_queue, process_id):
        firmware_analyser = FirmwareAnalyser(self.vendor, self.loglevel)
        
        # Get job from queue.
        for queue_input in iter(in_queue.get, 'STOP'):
            filename = str(queue_input).strip()
            print("\n\n[MAIN] Thread {1} - File {0}".format(
                filename, str(process_id)))
                
            # Get hash of file bytes.
            filebytes = open(filename, 'rb').read()
            m = hashlib.sha256(filebytes)
            # Don't waste resources by keeping file bytes in memory.
            filebytes = None
            # Get digest value.
            digest = m.hexdigest()
            outputfilename = './output/' + digest + '.json'
            
            # Get analysis output.
            try:
                output = firmware_analyser.analyse_firmware(filename)
                # If no output, but no error.
                if output == None:
                    out_queue.put(filename 
                                      + "," 
                                      + "None"
                                  )
                    in_queue.task_done()
                    continue
                # If an output was obtained.
                # Write to file.
                with open(outputfilename, 'w') as f: 
                    json.dump(output, f, indent=4)
                out_queue.put(filename)
                in_queue.task_done()
                continue
            except Exception as e:
                out_queue.put(filename 
                                  + "," 
                                  + "Error,"
                                  + str(e)
                              )
                in_queue.task_done()
            

if __name__ == '__main__':
    analysable_instance = SVCXtract()
    analysable_instance.start_analysis()