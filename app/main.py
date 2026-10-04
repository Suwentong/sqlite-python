import struct
import sys

# Page 1 is the sqlite_schema table. The 100-byte database header occupies
# the start of that page, and the 8-byte leaf table b-tree header follows it.
SCHEMA_PAGE_HEADER_OFFSET = 100
LEAF_TABLE_HEADER_SIZE = 8

# sqlite_schema columns, in record order.
SCHEMA_TYPE = 0
SCHEMA_TBL_NAME = 2

TEXT_ENCODINGS = {
    1: "utf-8",
    2: "utf-16-le",
    3: "utf-16-be",
}


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a SQLite varint. Returns (value, offset just past the varint)."""
    value = 0
    for index in range(8):
        byte = data[offset + index]
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            return value, offset + index + 1

    # The 9th byte, when present, contributes all 8 bits.
    return (value << 8) | data[offset + 8], offset + 9


def serial_type_size(serial_type: int) -> int:
    if serial_type <= 4:
        return serial_type
    if serial_type == 5:
        return 6
    if serial_type in (6, 7):
        return 8
    if serial_type in (8, 9):
        return 0
    if serial_type >= 12:
        # Even codes are blobs of (N-12)/2 bytes; odd codes are text of
        # (N-13)/2 bytes. Both lengths equal (N-12)//2.
        return (serial_type - 12) // 2
    raise ValueError(f"reserved serial type: {serial_type}")


def decode_column(serial_type: int, raw: bytes, encoding: str):
    if serial_type == 0:
        return None
    if 1 <= serial_type <= 6:
        return int.from_bytes(raw, byteorder="big", signed=True)
    if serial_type == 7:
        return struct.unpack(">d", raw)[0]
    if serial_type == 8:
        return 0
    if serial_type == 9:
        return 1
    if serial_type >= 12 and serial_type % 2 == 0:
        return raw
    if serial_type >= 13 and serial_type % 2 == 1:
        return raw.decode(encoding)
    raise ValueError(f"reserved serial type: {serial_type}")


def read_record(data: bytes, offset: int, encoding: str) -> list:
    """Parse a record (row) stored in SQLite record format."""
    header_size, cursor = read_varint(data, offset)
    header_end = offset + header_size

    serial_types = []
    while cursor < header_end:
        serial_type, cursor = read_varint(data, cursor)
        serial_types.append(serial_type)

    body = header_end
    values = []
    for serial_type in serial_types:
        size = serial_type_size(serial_type)
        values.append(decode_column(serial_type, data[body : body + size], encoding))
        body += size
    return values


def text_encoding(database: bytes) -> str:
    encoding_code = int.from_bytes(database[56:60], byteorder="big")
    return TEXT_ENCODINGS.get(encoding_code, "utf-8")


def schema_cell_offsets(database: bytes) -> list[int]:
    """Offsets of every cell on the sqlite_schema page, relative to the page start."""
    cell_count = int.from_bytes(
        database[SCHEMA_PAGE_HEADER_OFFSET + 3 : SCHEMA_PAGE_HEADER_OFFSET + 5],
        byteorder="big",
    )
    array_start = SCHEMA_PAGE_HEADER_OFFSET + LEAF_TABLE_HEADER_SIZE
    offsets = []
    for index in range(cell_count):
        pointer = array_start + index * 2
        offsets.append(int.from_bytes(database[pointer : pointer + 2], byteorder="big"))
    return offsets


def read_leaf_cell(database: bytes, cell_offset: int, encoding: str) -> list:
    """Parse a table b-tree leaf cell: payload size, rowid, then the record."""
    _, cursor = read_varint(database, cell_offset)
    _, cursor = read_varint(database, cursor)
    return read_record(database, cursor, encoding)


def user_table_names(database: bytes) -> list[str]:
    """Names of user tables, matching SQLite's .tables (skip sqlite_* internals)."""
    encoding = text_encoding(database)
    names = []
    for cell_offset in schema_cell_offsets(database):
        row = read_leaf_cell(database, cell_offset, encoding)
        tbl_name = row[SCHEMA_TBL_NAME]
        if row[SCHEMA_TYPE] == "table" and not tbl_name.startswith("sqlite_"):
            names.append(tbl_name)
    names.sort()
    return names


def main() -> None:
    database_file_path = sys.argv[1]
    command = sys.argv[2]

    with open(database_file_path, "rb") as database_file:
        database = database_file.read()

    if command == ".dbinfo":
        # Stage 1: database page size is a 2-byte big-endian value
        # immediately after the 16-byte magic string.
        page_size = int.from_bytes(database[16:18], byteorder="big")

        # Stage 2: sqlite_schema lives on page 1. The 100-byte file header
        # is part of that page, and the b-tree page header follows it.
        # Cell count is a 2-byte big-endian integer at page-header offset 3.
        # Each cell is one schema row, and this stage only has tables.
        number_of_tables = int.from_bytes(database[103:105], byteorder="big")

        print(f"database page size: {page_size}")
        print(f"number of tables: {number_of_tables}")
    elif command == ".tables":
        print(" ".join(user_table_names(database)))
    else:
        print(f"Invalid command: {command}")


if __name__ == "__main__":
    main()
