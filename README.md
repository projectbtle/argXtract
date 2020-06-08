# SVCXtract
SVCXtract enables the extraction of arguments to SVC Calls from stripped binaries. Vendor-specific customisation is required before the tool can be used.


## Requirements
Python 3.7+ (older versions will **not** work).

Install pre-requisites using `pip install -r requirements.txt`.

## Configuration
Even though parts of the tool are generic, it does not perform zero-knowledge analysis. Some vendor-specific information is required, and must be specified in a certain format. Details on how to do this are given in the [documentation](docs/vendor-config.md).


## Execution
```
usage: start.py [-h] (-d DIRECTORY | -f FILE | -l LIST) [-c [{c,e,w,i,d,t}]] [-m [{s,n}]]

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        directory containing firmware files to be analysed. Provide absolute path to directory as
                        argument.
  -f FILE, --file FILE  individual firmware file to be analysed.
  -l LIST, --list LIST  text file containing absolute paths of firmware files to be analysed.
  -c [{c,e,w,i,d,t}], --console [{c,e,w,i,d,t}]
                        console log level. One of c (critical), e (error), w (warning), i (info), d (debug), t
                        (trace).
  -m [{s,n}], --mode [{s,n}]
                        (trace) mode. Either s (strict) or n (non-strict). Strict mode checks conditions and follows
                        all relevant branches. It offers higher accuracy, but requires far greater processing power
                        and time. Non-strict mode (default) is more restrictive about which paths to follow. It offers
                        reasonable accuracy and much shorter processing times.
```


## Output
An individual JSON file is generated per analysed file, and all such output JSONs are placed within the `output` directory. The SHA256 hash of the file is used as the name for the output file, and the `hash,filepath` pairs are saved in 'fw_to_output.txt' within the root directory.