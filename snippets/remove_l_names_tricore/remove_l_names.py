from binaryninja import *

# Fix TriCore with symbols
for func in bv.functions:
    if func.name.startswith(".L"):
        bv.remove_user_function(func)

bv.reanalyze()
