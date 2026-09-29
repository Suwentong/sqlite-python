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
        print(f"database page size: {page_size}")
else:
    print(f"Invalid command: {command}")
