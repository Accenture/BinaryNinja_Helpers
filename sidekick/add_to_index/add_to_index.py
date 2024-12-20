
"""Indexer to find specified constants in HLIL with priority marking"""
from binaryninja import *

index_name = interaction.get_text_line_input("Provide Index Name","Create Index from Current Function:").decode()

if index_name:
    with open_index(bv, index_name) as index:
        index.add_entry(current_function, {})
