# Vendor-specific Configuration
In order to use SVCXtract, you must first provide some vendor-specific information. All vendor-specific information must be placed within the `svcxtract/resources/vendor/<vendor>` directory, where <vendor> is a unique name to identify the vendor/chipset of interest.

The following are required at a minimum:
* Size of application vector table.
* Possible values for application code base, and a mechanism for testing firmware to identify the correct app code base.
* Start address for disassembly. Normally, this is equal to the application code base.
* RAM base and RAM length.
* A set of SVC calls of interest, along with complete definitions for each.

This information can normally be obtained from the vendor's documentation.

## Chipset analysis code
Some code is required in order to check whether a firmware file matches the format for a specific vendor/chipset. This functionality must be present within a file called `chipset_analyser.py` within the `svcxtract/resources/vendor/<vendor>` directory. Details are given [here](chipset-analysis.md).

## SVC definition files
In order to perform SVC argument extraction and matching, the expected structure of the arguments must be known. This is specified within a JSON file, one file per SVC call, within `svcxtract/resources/vendor/<vendor>/svc/`. Details on the structure are provided [here](svc-definitions.md).

## Important notes
* The vendor/chipset name that is used must be unique and must be used consistently.
* The tool does not perform checks against multiple vendors and select a "best fit". Only one vendor is tested against. If configurations are provided for multiple vendors, then the vendor of interest must be specified when executing the tool, using the `-v` flag. The name that is specified must exactly match the vendor-specific folder name.
* SVC names can be anything, but must be the same in the SVC object that is defined within `chipset_analyser.py` and as names within the `svcxtract/resources/vendor/<vendor>/svc/` folder.