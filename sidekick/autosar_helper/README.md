# AUTOSAR Helper

Script that aims to assist when reverse engineering any AUTOSAR Classic based binary files by identifying the error handling and renaming functions based on the `Module` and `Service` numbers.

## Usage

1. Make sure to first load AUTOSAR CLassic types into the binary.
2. Try the scan option which will try to automatically detect error handling function.
3. If all fails but you manage to identify the function, use the feature to mark the current function as Det_ReportError. The plugin will rename all its cross-references accordingly.

## Notes

Brief notes for an easier start to reverse engineering AUTOSAR Classic Firmware can be found [here](https://app.heptabase.com/w/ca44b52a266c85ce09261eb92b240541d41160b4a1710deb97b1528ab55ed650)
