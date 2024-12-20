# Binary Ninja Helpers

This is a collection of scripts that can be used with snippets and sidekick plugins to enahcne the experience when doing reverse engineering.

## Contents

### Sidekick Files

* [Add To Index](./sidekick/add_to_index/) - This is a simple script that will create a named index from the current function. Great when tou want to trace relationship between multiple functions through Code Insight Map.
* [AUTOSAR Helper](./sidekick/autosar_helper/) - Script that aims to assist when reverse engineering any AUTOSAR Classic based binary files by identifying the error handling and renaming functions based on the `Module` and `Service` numbers.
* [Const Finder](./sidekick/const_finder/) - Indexer that can be used to find constants in the HLIL representaion that match specified criteria.
* [Function Finder](./sidekick/function_finder/) - Is useful when you suspect that a a lot of actual code was not detected by the analysis. This will try to find cross-refernces to the current function in the binary that are not associated with a function. Rare, but sometimes useful.
* [Kernel Symbols Import](./sidekick/kernel_symbols/) - Imports symbols from the `kallsyms` file.
* [Security Scanner](./sidekick/security_scanner/) - Script that will create Index with all potenially locations that may be subjects to interesting memory corruption issues. Use this in large binaries to filter out uninteresting points such as XREFs to `strcpy` that have static source operand.

### Snippets Files

* [ARM Fix](./snippets/arm_fix_address/) - In some weird files, the `Thumb` and `ARM` instruction sets can get mixed up. This should fix things but make sure to set the entry point of the ELF file correctly and select correct platform. This is just workaround until it gets fixed in core.
* [Inline Function](./snippets/inline_function/) - Inlines the current function. Very useful to have for any TriCore binaries.
* [Lift TriCore](./snippets/lift_tricore/) - Attempt to assign parameters to correct registers based on their type.
* [Remove .L Names](./snippets/remove_l_names_tricore/) - Some TriCore binaries come with symbols that make each line as a new function. This is not desirable and this snippet removes these functions for good.