[Quick link to Wiki](https://github.com/projectbtle/argXtract/wiki)


<br>

![argxtract_small](https://user-images.githubusercontent.com/29951305/103458078-9928f580-4cfc-11eb-8b3a-de2ed9bf490a.png)

<br>

## What is `argXtract`?
argXtract is a tool for extracting arguments to API calls (SVC calls and function calls) from within stripped IoT binaries (more specifically, ARM Cortex-M binaries). 

## Why would I want to extract arguments to API calls?
The configuration of an IoT device is very important from a security perspective. Many IoT devices operate on what we term a _split-firmware_ model, where a technology stack (such as Bluetooth Low Energy or Thread) is implemented by a vendor and the developer builds an application on top of it. In such cases, most of the configurations will be made via APIs provided by the vendor. For example, APIs may be provided to define access permissions, passwords, etc. Developers may also use libraries to perform additional configurations. By extracting the arguments to these configuration APIs, we can find out how secure a device is.

## How do I use `argXtract`?
To extract arguments from an API call, you need to provide details of the API call to `argXtract`. In particular, `argXtract` needs to know how to _find_ the API call within a stripped binary and how the arguments to the API call are _formatted_. For the former, you need to provide _function pattern files_ or details about supervisor calls. For the latter, you need to define _argument definition files_. We've provided a collection of function pattern files and argument definition files to start with. For details on how to define your own, head over to our [Wiki](https://github.com/projectbtle/argXtract/wiki).

```
usage: start.py [-h] (-d DIRECTORY | -f FILE | -l LIST) [-c [{c,e,w,i,d,t}]] [-b] [-t TIME_PER_TRACE] [-T TIME] -M [{s,f}] [-v VENDOR] [-p PROCESSES] [-F FUNCTIONS]
                [-a APP_CODE_BASE] [-m MAX_CALL_DEPTH] [-n [{n,l,s}]]
                
arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        directory containing firmware files to be analysed. Provide absolute path to directory as argument.
  -f FILE, --file FILE  individual firmware file to be analysed.
  -l LIST, --list LIST  text file containing absolute paths of firmware files to be analysed.
  -c [{c,e,w,i,d,t}], --console [{c,e,w,i,d,t}]
                        console log level. One of c (critical), e (error), w (warning), i (info), d (debug), t (trace).
  -b, --bypass          bypass all conditional checks.
  -t TIME_PER_TRACE, --time_per_trace TIME_PER_TRACE
                        maximum trace time per file, per start point in seconds.
  -T TIME, --Time TIME  maximum trace time per file in seconds.
  -M [{s,f}], --Mode [{s,f}]
                        analysis mode. Either s (SVC) or f (function).
  -v VENDOR, --vendor VENDOR
                        the vendor/chipset to test against. Vendor-specific files must be added to the repo.
  -p PROCESSES, --processes PROCESSES
                        number of parallel processes ("threads") to use.
  -F FUNCTIONS, --Functions FUNCTIONS
                        save function list to folder and exit.
  -a APP_CODE_BASE, --app_code_base APP_CODE_BASE
                        address at which application should be loaded.
  -m MAX_CALL_DEPTH, --max_call_depth MAX_CALL_DEPTH
                        maximum call depth of a function to be included in trace.
  -n [{n,l,s}], --null [{n,l,s}]
                        mechanism for handling null values (mainly those in LDR). One of n (none - do nothing), l (loose - keep track when LDR attempts to load from
                        outside RAM), s (strict - keep track when LDR attempts to load from any inaccessible memory location).

Note that this tool has only been tested with Python 3.7+. It will not work with lower versions.
```

So, to analyse a single Nordic Bluetooth Low Energy binary, you would use `python start.py -f <path_to_file -M s -v nordic_ble`.

The [Wiki](https://github.com/projectbtle/argXtract/wiki) has details about what each of the flags do, and the commands for running the individual examples with the `examples` folder.


### I don't get it. Maybe if you showed an example?
Consider the [`sd_ble_opt_set`](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.s132.api.v5.0.0%2Fgroup___b_l_e___c_o_m_m_o_n___f_u_n_c_t_i_o_n_s.html) API call provided by Nordic Semiconductors to configure options in Bluetooth Low Energy devices. One of the options it enables is the setting of a fixed pairing passkey. This can be accomplished using the following C code:
```c
uint8_t passkey[] = "123456"; 
ble_opt_t ble_opt; 
ble_opt.gap_opt.passkey.p_passkey = &passkey[0]; 
err_code = sd_ble_opt_set(BLE_GAP_OPT_PASSKEY, &ble_opt);   //BLE_GAP_OPT_PASSKEY = 34
```


Depending on the target chipset, `sd_ble_opt_set` corresponds to `svc` number `0x67` or `0x68`. We provide details about the `svc` numbers to `argXtract` to enable it to identify a call to `sd_ble_opt_set` within a disassembled Nordic BLE binary. 

As the C code shows, `sd_ble_opt_set` takes two arguments: an integer `opt_id` and a pointer to pointer to a passkey. We define this information in the following format:
```json
{
    "args": {
        "0": {
            "in_out": "in",
            "ptr_val": "value",
            "length": 4,
            "data": {
                "opt_id": {
                    "ptr_val": "value",
                    "length_bits": 32,
                    "type": "uint32"
                }
            }
        },
        "1": {
            "in_out": "in",
            "ptr_val": "pointer",
            "length": 6,
            "data": {
                "p_opt": {
                    "ptr_val": "pointer",
                    "length_bits": 48,
                    "type": "hex"
                }
            }
        }
    }
}
```

This would then produce the following output:
```json
 "output": {
    "sd_ble_opt_set": [
        {
            "opt_id": 34,
            "p_opt": "313233343536"
        }
    ]
 }
```
*Note: `0x313233343536` is hex for "123456", which is the string we provided as the fixed passkey.*

## Need more information?
Please check out the [Wiki](https://github.com/projectbtle/argXtract/wiki). It contains a detailed How-To and also explains the functionality of the tool in greater detail.

## Want to help out?
If you happen to have real-world Cortex-M binaries *with* headers (so that we can obtain accurate disassembly) that you're happy to share with us, please let us know. Ground truth is something we're lacking right now (so far, we're generating our own test files using different technologies and compilers, but real-world examples would be so much better). Please note, you must have the right to share the binaries! 

We'd also like to speed up our function pattern matching module. Anyone with ideas, please reach out!
