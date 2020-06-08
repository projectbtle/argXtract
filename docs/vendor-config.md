In order to use SVCXtract, you must first provide some vendor-specific information. The following are required at a minimum:
* Size of application vector table.
* Possible values for application code base, and a mechanism for testing firmware to identify the correct app code base.
* Start address for disassembly. Normally, this is equal to the application code base.
* A set of SVC calls of interest, along with complete definitions for each.

All vendor-specific information must be placed within the `svcxtract/resources/vendor/<vendor>` directory, where <vendor> is a unique name to identify the vendor/chipset of interest.