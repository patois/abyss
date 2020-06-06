# abyss - Postprocess Hexrays Decompiler Output

## Installation
Copy abyss.py and abyss_filters to IDA plugins directory

## Usage
Right-click within a decompiler view, pick a filter
from the abyss context menu.

Per-filter default settings can be changed by editing
the config file: "%APPDATA%/Hex-Rays/IDA Pro/plugins/abyss.cfg"

## Disclaimer
Experimental/WIP code, use at your own risk :)

## Developers
Create a fresh Python module within "abyss_filters", make sure
to inherit from the abyss_filter_t class (see abyss.py).

Re-running the plugin from the plugins menu or by pressing
the Ctrl-Alt-R keycombo reloads all filters dynamically.
This allows for development of filters without having to
restart IDA.

## Example filters

### signed_ops.py (identify signed operators)
![abyss signedops gif](/rsrc/signedops.gif?raw=true)

### lvars_info.py (append additional info to variable names)
![abyss lvars gif](/rsrc/lvars.gif?raw=true)

### func_colorizer.py (colorize function names)
![abyss func gif](/rsrc/func.gif?raw=true)
