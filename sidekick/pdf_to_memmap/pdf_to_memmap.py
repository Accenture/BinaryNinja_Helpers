import pdfplumber
import re
#from binaryninja import *


DEBUG = False

def guess_brand(pdf_file):
    with pdfplumber.open(pdf_file) as pdf:
        for page in pdf.pages[:20]:
            page_text = page.extract_text_simple(x_tolerance=3, y_tolerance=3).upper()
            if "INFINEON" in page_text:
                return "Infineon"
            elif "NXP" in page_text:
                return "NXP"
            elif "RENESAS" in page_text:
                return "Renesas"

# INFINEON START---------------------------------------------------------------------
def extract_infineon_pdf(pdf_file):
    sections_array = []
    with pdfplumber.open(pdf_file) as pdf:
        next_start = 0
        in_memmap_section = False # MEMMAP
        #print(pdf.pages[223].extract_text_simple(x_tolerance=3, y_tolerance=3).upper())
        for page in pdf.pages:
            page_text = page.extract_text_simple(x_tolerance=3, y_tolerance=3)
            if "..............." not in page_text and ". . . . . . . . . . ." not in page_text:
                if "MEMMAPV" in page_text:
                    in_memmap_section = True
                    tables = page.extract_tables()
                    for table in tables:
                        for row in table:
                            if len(row) > 2:
                                #print(row)
                                if row[0]:
                                    end_addr = row[0]
                                    if end_addr[-1] == "H":
                                        end_addr = end_addr[:-1]
                                    if end_addr[-1] == "\n":
                                        end_addr = end_addr[:-1]
                                    end_addr = int(end_addr,16)
                                    if row[2] != "Reserved":
                                        sections_array.append({"start":next_start,"end":end_addr, "name":' '.join(row[2].splitlines())})
                                        #print(f"{hex(next_start)} - {hex(end_addr)} ({' '.join(row[2].splitlines())})")
                                    next_start = end_addr + 1
                elif "MemMaps" in page_text:
                    in_memmap_section = True
                    tables_lines = page.extract_tables({
                                    "vertical_strategy": "lines", 
                                    "horizontal_strategy": "lines",
                                    "snap_tolerance": 2,
                                    "snap_x_tolerance": 2,
                                    "snap_y_tolerance": 2,
                                    "join_tolerance": 2,
                                    "join_x_tolerance": 2,
                                    "join_y_tolerance": 2,
                                    "edge_min_length": 0,
                                })
                    for table in tables_lines:
                        for row in table:
                            if row[0]:
                                address_range = infineon_parse_addr_range_helper(row[0])
                                if address_range and len(row) > 3 and row[2] and "RESERVED" not in row[2].upper():
                                    sections_array.append({"start":address_range[0],"end":address_range[1], "name":' '.join(row[2].splitlines())})
                    tables_text = page.extract_tables({
                                    "vertical_strategy": "text", 
                                    "horizontal_strategy": "lines",
                                    "snap_tolerance": 2,
                                    "snap_x_tolerance": 2,
                                    "snap_y_tolerance": 2,
                                    "join_tolerance": 2,
                                    "join_x_tolerance": 2,
                                    "join_y_tolerance": 2,
                                    "edge_min_length": 0,
                                })
                    for table in tables_text:
                        for row in table:
                            if len(row) > 2 and len(row) < 10 and row[1] and row[0]:
                                address_range = infineon_parse_addr_range_helper(row[1])
                                if address_range and "RESERVED" not in row[0].upper():
                                    sections_array.append({"start":address_range[0],"end":address_range[1], "name":' '.join(row[0].splitlines())})
                elif in_memmap_section:
                    break
    if DEBUG:
        print(sections_array)
    else:
        add_sections(sections_array)


def infineon_parse_addr_range_helper(table_field):
    if " " not in table_field:
        return None
    tmp_data = table_field.replace(" ","").replace("\nH", "").replace("-","").split("\n")
    try:
        return [int(tmp_data[0],16),int(tmp_data[1],16)]
    except:
        return None

# INFINEON END---------------------------------------------------------------------

# RENESAS START -------------------------------------------------------------------
def extract_renesas_pdf(pdf_file):
    sections_array = []
    with pdfplumber.open(pdf_file) as pdf:
        next_start = 0
        in_memmap_section = False # MEMMAP
        for page in pdf.pages:
            page_text = page.extract_text_simple(x_tolerance=3, y_tolerance=3)
            if "...................." not in page_text:
                if "Peripheral I/O Address Map" in page_text:
                    in_memmap_section = True
                    tables = page.extract_tables()
                    for table in tables:
                        for row in table:
                            if DEBUG:
                                print(row)
                            if row[2] != "Access prohibited area" and row[0] != "Address":
                                address_range = renesas_parse_addr_range_helper(row[0])
                                if address_range:
                                    sections_array.append({"start":address_range[0],"end":address_range[1], "name":' '.join(row[2].splitlines())})
                elif in_memmap_section:
                    break
    if DEBUG:
        print(sections_array)
    else:
        add_sections(sections_array)

def renesas_parse_addr_range_helper(table_field):
    tmp_data = table_field.replace(" ","").replace("\nHH", "").split("to")
    try:
        return [int(tmp_data[0],16),int(tmp_data[1],16)]
    except Exception as e:
        print(e)
        return None

# RENESAS END ---------------------------------------------------------------------


def add_sections(sections_array):
    for section in sections_array:
        bv.add_user_segment(section["start"],section["end"] - section["start"],0,0,enums.SegmentFlag.SegmentWritable | enums.SegmentFlag.SegmentReadable)
        bv.add_user_section(section["name"],section["start"],section["end"] - section["start"])

#pdf_file_path = "/tmp/rh850.pdf"
pdf_file_path = interaction.get_open_filename_input("Select PDF file", "*.pdf")
match guess_brand(pdf_file_path):
    case "Infineon":
        extract_infineon_pdf(pdf_file_path)
    case "NXP":
        print("Not handled yet")
    case "Renesas":
        extract_renesas_pdf(pdf_file_path)
    case _:
        print("Not possible to tell")


