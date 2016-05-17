# FilterFixer
Easily move Barracuda filters from BESG to BESS

This program will change the formatting from BESG style to BESS style, sorting the output if not already sorted to begin with.
#####New in v1.0: Duplicates can now be removed using the Dedupe page.
 * The dedupe function will only remove duplicate entries and report the entries that were removed, the filter will *not* be converted to BESS format
 * The various converting functions will automatically remove dupes as part of the conversion process.

## Usage
1. Copy the filter you are looking to move from the Bulk Edit section of the appliance.
2. Paste the list into the text box for that filter. If just looking to remove dupes, use the Dedupe page.
3. Hit Convert.
4. Copy and paste the resulting filter. That's it.

#### Notes
* Allowed and blocked lists for IP and Sender filters can be added at the same time, they will be combined into a single list
* Any Recipient block entries will be removed as these are not supported by BESS
* Tag will always be changed to Quarantine and filters not supporting Quarantine will be set to Block instead
