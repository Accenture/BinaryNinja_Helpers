# Security Scanner

Script that will create Index with all potenially locations that may be subjects to interesting memory corruption issues. Use this in large binaries to filter out uninteresting points such as XREFs to `strcpy` that have static source operand.