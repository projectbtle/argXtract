# Vendor-specific Configuration
In order to use argXtract, you must first provide some vendor-specific information. All vendor-specific information must be placed within the `argxtract/resources/vendor/<vendor>` directory, where <vendor> is a unique name to identify the vendor/chipset of interest.

The following are required at a minimum:
* A set of SVC calls of interest, along with complete definitions for each. [SVC analysis mode]
* A set of function signatures of interest. [Function analysis mode]

## Chipset analysis code
Some code is required in order to check whether a firmware file matches the format for a specific vendor/chipset. This functionality must be present within a file called `chipset_analyser.py` within the `argxtract/resources/vendor/<vendor>` directory. Details are given [here](chipset-analysis.md).

## COI definition files
In order to perform COI argument extraction and matching, the expected structure of the arguments must be known. This is specified within a JSON file, one file per COI, within `argxtract/resources/vendor/<vendor>/args/`. Details on the structure are provided [here](arg-definitions.md).

## Important notes
* The vendor/chipset name that is used must be unique and must be used consistently.
* The tool does not perform checks against multiple vendors and select a "best fit". Only one vendor is tested against. If configurations are provided for multiple vendors, then the vendor of interest must be specified when executing the tool, using the `-v` flag. The name that is specified must exactly match the vendor-specific folder name.
* COI names can be anything, but must be the same in the SVC/function object that is provided within `chipset_analyser.py` and as names within the `argxtract/resources/vendor/<vendor>/args/` folder.