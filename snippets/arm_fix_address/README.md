# ARM Fixup

In some weird files, the `Thumb` and `ARM` instruction sets can get mixed up. This should fix things but make sure to set the entry point of the ELF file correctly and select correct platform. This is just workaround until it gets fixed in core.