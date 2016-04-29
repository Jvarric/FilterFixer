# FilterFixer
Easily move Barracuda filters from BESG to BESS

This program will change the formatting from BESG style to BESS style, sorting the output if not already sorted to begin with.
Currently duplicate entries are not removed, but a sorted list does make these much easier to locate.

## Usage
1. Copy the filter you are looking to move from the Bulk Edit section of the appliance.
2. Paste this list into the text box for that filter.
3. Hit Convert.
4. Paste the resulting filter into BESS. That's it.

#### Notes
* Allowed and blocked lists for IP and Sender filters can be added at the same time, they will be combined into a single list
* Any Recipient block entries will be removed as these are not supported by BESS
* Any action of Tag on the appliance filters will be changed to Quarantine upon conversion, as Tag is not supported by BESS
