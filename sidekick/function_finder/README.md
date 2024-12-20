# Functions Finder

Script to find XREFs to current functions that may be hidden in the code that was not discovered during the initial analysis. Usually not necessary but sometimes useful. Sidekick index will be created with all spots that are not functions but contain instructions that XREF the current function. This is helpful with logging functions which are called very often.
Furthermore, the script will also automatically search for the occurrence of the address of the function within the selected segment. This is something you can do with simple byte search, but this way it will organize the references in same index for better readability.
