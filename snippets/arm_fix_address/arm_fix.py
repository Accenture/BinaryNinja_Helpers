from binaryninja import *

# Fix ARM ELFs with incorrect address
for func in bv.functions:
    start = func.start
    bv.remove_user_function(func)
    bv.add_function(start)

bv.reanalyze()
