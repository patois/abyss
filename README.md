# abyss
## Postprocess Hexrays Decompiler Output

### Installation
Copy abyss.py and abyss_filters to IDA plugins directory

### Usage
Right-click within a decompiler view, pick a filter
from the abyss context menu.

### Disclaimer
Experimental/WIP code, use at your own risk :)

### Developers
Create a fresh Python module within "abyss_filters", make sure
to inherit from the abyss_filter_t class (see abyss.py).

### Example filters

#### signed_ops.py
![abyss signedops gif](/rsrc/signedops.gif?raw=true)

#### lvars_info.py
![abyss lvars gif](/rsrc/lvars.gif?raw=true)

#### func_colorizer.py
![abyss func gif](/rsrc/func.gif?raw=true)
