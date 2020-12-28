import os
import sys
import json
import shutil
import hashlib
import logging
import argparse
from time import sleep
from argxtract.common import objects as common_objs
from argxtract.core import consts
from argxtract.core.analyser import FirmwareAnalyser
from multiprocessing import Process, JoinableQueue, active_children


class argxtract:
    def __init__(self):
        self.vendor = None
        self.function_folder = None
        self.mode = consts.MODE_SVC
        self.processes = 1
        self.bypass = False
        self.max_time = common_objs.max_time
        self.per_trace_max_time = common_objs.per_trace_max_time
        self.max_call_depth = common_objs.max_call_depth
        self.null_handling = common_objs.null_value_handling
        self.app_code_base = None
        self.core_file_list = []
        self.loglevel = logging.INFO
        logging.getLogger().setLevel(self.loglevel)
        self.set_args()
        self.check_args()
        
    def set_args(self):
        self.argparser = argparse.ArgumentParser(
            description = 'argxtract enables testing stripped IoT firmware '
                          + 'files to extract arguments to configuration constructs '
                          + ' (such as Supervisor Calls or function calls).',
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
            '-b',
            '--bypass',
            action = 'store_true',
            help = 'bypass all conditional checks.'
        )
        self.argparser.add_argument(
            '-t',
            '--time_per_trace',
            type = int,
            action = 'store',
            help = 'maximum trace time per file, per start point in seconds.'
        )
        self.argparser.add_argument(
            '-T',
            '--Time',
            type = int,
            action = 'store',
            help = 'maximum trace time per file in seconds.'
        )
        self.argparser.add_argument(
            '-M',
            '--Mode',
            type = str,
            choices = ['s', 'f'],
            action = 'store',
            nargs = '?',
            required=True,
            help = 'analysis mode. '
                   + 'Either s (SVC) '
                   + 'or f (function).'
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
        self.argparser.add_argument(
            '-F',
            '--Functions',
            type = str,
            action = 'store',
            help = 'save function list to folder and exit.'
        )
        self.argparser.add_argument(
            '-a',
            '--app_code_base',
            type = str,
            action = 'store',
            help = 'address at which application should be loaded.'
        )
        self.argparser.add_argument(
            '-m',
            '--max_call_depth',
            type = int,
            action = 'store',
            help = 'maximum call depth of a function to be included in trace.'
        )
        self.argparser.add_argument(
            '-n',
            '--null',
            type = str,
            choices = ['n', 'l', 's'],
            action = 'store',
            nargs = '?',
            help = 'mechanism for handling null values (mainly those in LDR). '
                   + 'One of n (none - do nothing), '
                   + 'l (loose - keep track when LDR attempts to load from outside RAM), '
                   + 's (strict - keep track when LDR attempts to load from any inaccessible memory location).'
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
                    if (not (fw_file.endswith('.bin'))):
                        continue
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
                if (not (fw_file.endswith('.bin'))):
                    continue
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
            if (not (filepath.endswith('.bin'))):
                logging.critical(
                    'Not a bin file '
                    + filepath
                )
                sys.exit(0)
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
            
        if args.Time:
            if args.Time > 0:
                self.max_time = args.Time
        else:
            self.max_time = 0
                
        if args.time_per_trace:
            if args.time_per_trace > 0:
                self.per_trace_max_time = args.time_per_trace
        else:
            self.per_trace_max_time = 0
    
        if args.max_call_depth != None:
            if args.max_call_depth >= 0:
                self.max_call_depth = args.max_call_depth

        if args.Mode:
            if args.Mode == 'f':
                self.mode = consts.MODE_FUNCTION
            else:
                self.mode  = consts.MODE_SVC
        
        if args.Functions:
            if (not (os.path.isdir(args.Functions))):
                print('Function folder does not exist!')
                sys.exit(0)
            self.function_folder = args.Functions
            
        if args.processes:
            if args.processes > 0:
                self.processes = args.processes
                
        if args.app_code_base:
            if args.app_code_base.startswith('0x'):
                try:
                    app_code_base = int(args.app_code_base, 16)
                except:
                    print('Could not convert app code base to int!')
                    sys.exit(0)
            else:
                try:
                    app_code_base = int(args.app_code_base)
                except:
                    print('Could not convert app code base to int!')
                    sys.exit(0)
            self.app_code_base = app_code_base
            
        if args.null:
            self.null_handling = args.null
            
        if args.bypass:
            self.bypass = True
            
        if ((self.max_time == 0) and (self.per_trace_max_time == 0)):
            self.max_time = common_objs.max_time
            
    def start_analysis(self):
        # Banner.
        print(
            '\n==================================\n'
            + 'argxtract\n'
            + '==================================\n'
        )
        
        logging.info(
            str(len(self.core_file_list))
            + ' firmware files to analyse.'
        )

        # Create temporary folder.
        logging.info('Creating tmp directory for working files.')
        if (not (os.path.isdir('tmp'))):
            os.mkdir('tmp')
        else:
            logging.debug('Deleting previous tmp directory.')
            shutil.rmtree('tmp')
            sleep(2)
            os.mkdir('tmp')
        
        # Create output folder.
        if (not (os.path.isdir('output'))):
            logging.info('Creating output directory.')
            os.mkdir('output')
            
        if self.processes == 1:
            self.execute_single_process()
        else:
            self.execute_multiple_processes()
            
        # Remove the temporary directory and all files within.
        logging.info('Cleaning up..')
        shutil.rmtree('tmp')
            
    def execute_single_process(self):
        firmware_analyser = FirmwareAnalyser(
            self.mode,
            self.vendor, 
            self.max_time,
            self.per_trace_max_time,
            self.function_folder,
            self.max_call_depth,
            self.loglevel,
            self.null_handling,
            self.bypass,
            0
        )
        outfile = open('status.csv', 'w')
        for fw_file in self.core_file_list:
            ###try:
            # Get hash of file bytes.
            filebytes = open(fw_file, 'rb').read()
            m = hashlib.sha256(filebytes)
            # Don't waste resources by keeping file bytes in memory.
            filebytes = None
            # Get digest value.
            digest = m.hexdigest()
            outputfilename = './output/' + digest + '.json'
            # Get analysis output.
            output = firmware_analyser.analyse_firmware(fw_file, self.app_code_base)
            if output == None:
                outfile.write(fw_file + ',None\n')
                outfile.flush()
                continue
            if self.function_folder != None:
                continue
            # Write to file.
            with open(outputfilename, 'w') as f: 
                json.dump(output, f, indent=4)
            outfile.write(fw_file + ',Completed,None\n')
            outfile.flush()
            ###except Exception as e:
            ###    outfile.write(fw_file + ',Error,' + str(e) + '\n')
            ###    outfile.flush()
                
    def execute_multiple_processes(self):
        # We don't want long messages in parallel threads.
        self.loglevel = logging.CRITICAL
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
            workerx = argxtractWorker(
                self.mode,
                self.vendor, 
                self.max_time,
                self.per_trace_max_time,
                self.function_folder,
                self.max_call_depth,
                self.loglevel,
                self.null_handling,
                self.bypass,
                self.app_code_base
            )
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
        outfile = open('status.csv', 'w')
        
        while True:
            #Get and process information sent by worker process.
            result = process_receive_queue.get()
            process_receive_queue.task_done()
            
            # Log, etc.
            split_result = result.split(',')
            filename = split_result[0]
            print('Finished analysing ' + filename)
            if len(split_result) > 1:
                status = split_result[1]
            else:
                status = 'Completed'
            if len(split_result) > 2:
                error = split_result[2]
            else:
                error = 'None'
            outfile.write(filename + ',' + status + ',' + error + '\n')
            outfile.flush()
            
            #Check if any processes have become zombies.
            if len(active_children()) < self.processes:
                for p in process_list:
                    if not p.is_alive():
                        process_list.remove(p)
                        # Create replacement worker.
                        workerx = argxtractWorker(
                            self.mode,
                            self.vendor, 
                            self.max_time,
                            self.per_trace_max_time,
                            self.function_folder,
                            self.max_call_depth,
                            self.loglevel,
                            self.null_handling,
                            self.bypass,
                            self.app_code_base
                        )
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
            

class argxtractWorker:
    def __init__(self, mode, vendor, max_time, per_trace_max_time, function_folder, 
            max_call_depth, loglevel, null_handling, bypass, app_code_base):
        self.mode = mode
        self.vendor = vendor
        self.bypass = bypass
        self.max_time = max_time
        self.per_trace_max_time = per_trace_max_time
        self.function_folder = function_folder
        self.max_call_depth = max_call_depth
        self.loglevel = loglevel
        self.null_handling = null_handling
        self.app_code_base = app_code_base
        logging.getLogger().setLevel(loglevel)
        
    def main(self, in_queue, out_queue, process_id):
        firmware_analyser = FirmwareAnalyser(
            self.mode,
            self.vendor, 
            self.max_time,
            self.per_trace_max_time,
            self.function_folder,
            self.max_call_depth,
            self.loglevel,
            self.null_handling,
            self.bypass,
            process_id
        )

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
                output = firmware_analyser.analyse_firmware(filename, self.app_code_base)
                # If no output, but no error.
                if output == None:
                    if self.function_folder != None:
                        out_queue.put(filename 
                                      + "," 
                                      + "FunctionsSaved"
                                  )
                    else:
                        out_queue.put(filename 
                                          + "," 
                                          + "None"
                                      )
                    in_queue.task_done()
                    sleep(2)
                    continue
                # If an output was obtained.
                # Write to file.
                with open(outputfilename, 'w') as f: 
                    json.dump(output, f, indent=4)
                out_queue.put(filename)
                in_queue.task_done()
                sleep(2)
                continue
            except Exception as e:
                out_queue.put(filename 
                                  + "," 
                                  + "Error,"
                                  + str(e)
                              )
                in_queue.task_done()
                sleep(2)
                continue

if __name__ == '__main__':
    analysable_instance = argxtract()
    analysable_instance.start_analysis()