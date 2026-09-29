import sys

from dataclasses import dataclass

# import sqlparse - available if you need it!

database_file_path = sys.argv[1]
command = sys.argv[2]

if command == ".dbinfo":
    with open(database_file_path, "rb") as database_file:
        # Stage 1: database page size is a 2-byte big-endian value
        # immediately after the 16-byte magic string.
        database_file.seek(16)
        page_size = int.from_bytes(database_file.read(2), byteorder="big")

        # Stage 2: sqlite_schema lives on page 1. The 100-byte file header
        # is part of that page, and the b-tree page header follows it.
        # Cell count is a 2-byte big-endian integer at page-header offset 3.
        # Each cell is one schema row, and this stage only has tables.
        database_file.seek(103)
        number_of_tables = int.from_bytes(database_file.read(2), byteorder="big")

        print(f"database page size: {page_size}")
        print(f"number of tables: {number_of_tables}")
else:
    print(f"Invalid command: {command}")
