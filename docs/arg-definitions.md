# SVC Definitions

An SVC definition is essentially a JSON file describing the structure of arguments to a specific SVCall. One SVCall can only have one associated SVC definition file, and the name of the file must be the same as the name of the SVC as defined within the vendor-specific plugin code.

## The structure of an SVC definition file
As mentioned before, an SVC definition file is simply a JSON file. The top-level keys are strings representing integer indices of arguments. That is, an SVCall that has two arguments would have a definition file with two top-level keys "0" and "1". Keys must be contiguous. If you're not interested in an intermediate argument, you would still need to have dummy keys (e.g., if an SVCall has three arguments and you only want the first and last arguments, you would still need all 3 keys: "0", "1", "2"). Of course, if you don't care about the *last* argument, you can always leave it out.

## Keys and values
An SVC definition file has certain keys, which each have a set of possible values. 

| Key | Possible Values | Usage |
|-----|-------|-------|
| "in_out" | "in", "out", "<>_out" | Second-level only. Used to indicate whether an argument is an input or an output. |
| "ptr_val" | "pointer", "value" | Used to indicate whether an argument (or an element) is a value or a pointer to a value (or to another pointer) |
| "type" | "dict", "hex", "bitfield", "int8", "uint8", "int16", "uint16" | The format of the data value. |
| "length_bits" | \<integer\> | Length of the value in bits. |
| "data" | \<dictionary structure\> | Describes the structure of an argument or element. |


## Example
For our example, let's assume we have an SVCall with SVC number 0xa0 that we'll name *SampleSVC*, i.e., the SVC is present within the vendor-specific SVC object as follows:
```
{
    ...,
    "SampleSVC": "0xa0",
    ...    
}
```

The SVC definition file must therefore be named `SampleSVC.json`.


Our SampleSVC has 3 arguments: the first two are inputs and the last is an output. The SVCall is defined as follows:
```
SampleSVC(uint16 arg0, struct0 const *arg1, struct1 const *arg2);
```

The first argument, `arg0`, is an unsigned integer, while `arg1` and `arg2` are pointers to data structures.


The skeleton SVC definition file will therefore look as below:
```
{
    "0": {
        "in_out": "in",
        "ptr_val": "value",
        "data": {
        
        }
    },
    "1": {
        "in_out": "in",
        "ptr_val": "pointer",
        "data": {
        
        }
    },
    "2": {
        "in_out": "out",
        "ptr_val": "pointer",
        "data": {
        
        }
    }
}
```

When this SVCall is reached during the trace, the values in registers R0 to R2 will correspond to these arguments.

### `arg0`
The first argument, `arg0`, is an unsigned integer. That is, the register R0 will hold the *value* to be used for `arg0` directly. The "data" key will therefore have the following value:
```
"data": {
  "arg0": {
      "ptr_val": "value",
      "length_bits": 16,
      "type": "uint16"
  }
}
```

This will look as below in the JSON file.
```
{
    "0": {
        "in_out": "in",
        "ptr_val": "value",
        "data": {
            "arg0": {
                "ptr_val": "value",
                "length_bits": 16,
                "type": "uint16"
            }
        }
    },
    "1": {
        "in_out": "in",
        "ptr_val": "pointer",
        "data": {
        
        }
    },
    "2": {
        "in_out": "out",
        "ptr_val": "pointer",
        "data": {
        
        }
    }
}
```

### `arg1`
Let's say the struct0 data structure is defined as follows:
```
typedef struct
{
  uint8_t element0;
  uint8_t *element1;
  struct2 element2;
} struct0;
```

The first element is a value, the second is a pointer to an array of uint8 values and the third is defined by another structure.

The "data" key for `arg1` would have an outline as follows:
```
"data": {
  "arg1": {
    "ptr_val": "value",
    "length_bits": TBD,
    "type": "dict",
    "data": {
      "element0": {
        "ptr_val": "value",
        "length_bits": 8,
        "type": "uint8"
      },
      "element1": {
        "ptr_val": "pointer",
        "length_bits": 8,
        "type": "uint8"
      },
      "element2": {
        "ptr_val": "value",
        "length_bits": TBD,
        "type": "dict",
        "data": {}
      },
    }
  }
}
```

We would then need to examine the structure of struct2 as we did for struct0 and fill out the "data" key. The "length_bits" value will depend on the length of struct2. Let's say the total length of elements in struct2 comes to 64 bits. Then the "length_bits" for `arg1` will be 8+8+64 = 80.

### `arg2`
Sometimes an SVCall will store some values to an output structure, e.g., handles. Obviously, `argXtract` won't be able to get actual values for such elements. However, it can assign a random value to be used (with another SVCall) if needed.

Let's assume `arg2` is an output argument that assigns two handles:
```
typedef struct
{
  uint16_t handle0;
  uint16_t handle1;
} struct1;
```

The "data" key for `arg2` will then be defined as follows:
```
"data": {
  "arg2": {
    "ptr_val": "value",
    "length_bits": 32,
    "type": "dict",
    "data": {
      "handle0": {
        "ptr_val": "pointer",
        "length_bits": 16,
        "type": "hex",
        "store_type": "random",
        "output": true
      },
      "handle1": {
        "ptr_val": "pointer",
        "length_bits": 16,
        "type": "hex",
        "store_type": "random",
        "output": true
      }
    }
  }
}
```

The `"store_type": "random"` tells `argXtract` to assign random values to each element. `"output": true` tells it to store those values in its "memory map".
