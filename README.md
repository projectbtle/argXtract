[Quick link to Wiki](https://github.com/projectbtle/argXtract/wiki)

## What is `argXtract`?
argXtract is a tool for extracting arguments to API calls (SVC calls and function calls) from within stripped IoT binaries (more specifically, ARM Cortex-M binaries). 

## Why would I want to extract arguments to API calls?
The configuration of an IoT device is very important from a security perspective. Many IoT devices operate on what we term a _split-firmware_ model, where a technology stack (such as Bluetooth Low Energy or Thread) is implemented by a vendor and the developer builds an application on top of it. In such cases, most of the configurations will be made via APIs provided by the vendor. For example, APIs may be provided to define access permissions, passwords, etc. By extracting the arguments to these configuration APIs, we can find out how secure a device is.

## How do I use `argXtract`?
To extract arguments from an API call, you need to provide details of the API call to `argXtract`. In particular, `argXtract` needs to know how to _find_ the API call within a stripped binary and how the arguments to the API call are _formatted_. For the former, you need to provide _function pattern files_ or details about supervisor calls. For the latter, you need to define _argument definition files_. 

### Example
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

## Need more information?
Please check out the [Wiki](https://github.com/projectbtle/argXtract/wiki). It contains a detailed How-To and also explains the functionality of the tool in greater detail.


