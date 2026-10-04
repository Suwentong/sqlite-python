import bisect
import mmap
import struct
import sys
from collections.abc import Iterator

import sqlparse
from sqlparse.sql import Comparison, Identifier, IdentifierList, Where

# Page 1 is the sqlite_schema table. The 100-byte database header occupies
# the start of that page, and the 8-byte leaf table b-tree header follows it.
SCHEMA_PAGE_HEADER_OFFSET = 100
LEAF_TABLE_HEADER_SIZE = 8
INTERIOR_TABLE_HEADER_SIZE = 12
LEAF_TABLE_PAGE_TYPE = 0x0D
INTERIOR_TABLE_PAGE_TYPE = 0x05
LEAF_INDEX_PAGE_TYPE = 0x0A
INTERIOR_INDEX_PAGE_TYPE = 0x02

# sqlite_schema columns, in record order.
SCHEMA_TYPE = 0
SCHEMA_TBL_NAME = 2
SCHEMA_ROOTPAGE = 3
SCHEMA_SQL = 4

# First token of a table-level constraint, as sqlparse emits it.
TABLE_CONSTRAINTS = {
    "CONSTRAINT",
    "PRIMARY",
    "PRIMARY KEY",
    "UNIQUE",
    "CHECK",
    "FOREIGN",
    "FOREIGN KEY",
}

# Tokens that end a column type name. "PRIMARY KEY" may arrive as one token
# or as the separate words PRIMARY and KEY.
COLUMN_CONSTRAINTS = TABLE_CONSTRAINTS | {
    "KEY",
    "NOT",
    "NOT NULL",
    "NULL",
    "DEFAULT",
    "COLLATE",
    "REFERENCES",
    "GENERATED",
    "AS",
    "AUTOINCREMENT",
    "ON",
}

TEXT_ENCODINGS = {
    1: "utf-8",
    2: "utf-16-le",
    3: "utf-16-be",
}


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a SQLite varint. Returns (value, offset just past the varint)."""
    byte = data[offset]
    if byte < 0x80:
        return byte, offset + 1

    value = byte & 0x7F
    for index in range(1, 8):
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


def read_record(
    data: bytes, offset: int, encoding: str, columns: set[int] | None = None
) -> list:
    """Parse a record (row) stored in SQLite record format.

    `columns`, when set, names the indexes to decode. Later columns are not
    read at all. Every other value up to the last requested one is None, and
    its body is skipped rather than turned into a string or blob.
    """
    header_size, cursor = read_varint(data, offset)
    header_end = offset + header_size
    last = None if columns is None else (max(columns) if columns else -1)

    serial_types = []
    while cursor < header_end and (last is None or len(serial_types) <= last):
        serial_type, cursor = read_varint(data, cursor)
        serial_types.append(serial_type)

    body = header_end
    values = []
    for index, serial_type in enumerate(serial_types):
        size = serial_type_size(serial_type)
        if columns is not None and index not in columns:
            values.append(None)
        else:
            values.append(decode_column(serial_type, data[body : body + size], encoding))
        body += size
    return values


def text_encoding(database: bytes) -> str:
    encoding_code = int.from_bytes(database[56:60], byteorder="big")
    return TEXT_ENCODINGS.get(encoding_code, "utf-8")


def page_size(database: bytes) -> int:
    """Database page size. A stored value of 1 means 65536."""
    size = int.from_bytes(database[16:18], byteorder="big")
    return 65536 if size == 1 else size


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


def table_definition(database: bytes, table_name: str) -> tuple[int, str]:
    """Root page and CREATE TABLE statement for a user table."""
    encoding = text_encoding(database)
    for cell_offset in schema_cell_offsets(database):
        row = read_leaf_cell(database, cell_offset, encoding)
        if row[SCHEMA_TYPE] == "table" and row[SCHEMA_TBL_NAME] == table_name:
            return row[SCHEMA_ROOTPAGE], row[SCHEMA_SQL]
    raise ValueError(f"no such table: {table_name}")


def table_rootpage(database: bytes, table_name: str) -> int:
    """Root page number of a user table, from its sqlite_schema row."""
    return table_definition(database, table_name)[0]


def page_cell_count(database: bytes, page_number: int) -> int:
    """Number of cells on a b-tree page. On a leaf table page, that is the row count."""
    page_offset = (page_number - 1) * page_size(database)
    # Page 1 begins with the 100-byte database header; later pages do not.
    header_offset = page_offset + (SCHEMA_PAGE_HEADER_OFFSET if page_number == 1 else 0)
    return int.from_bytes(database[header_offset + 3 : header_offset + 5], byteorder="big")


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


def unquote_identifier(name: str) -> str:
    if len(name) >= 2 and name[0] == name[-1] and name[0] in "\"'`":
        return name[1:-1]
    if name.startswith("[") and name.endswith("]"):
        return name[1:-1]
    return name


def table_columns(create_sql: str) -> list[tuple[str, bool]]:
    """Columns in CREATE TABLE order.

    The flag is true for an INTEGER PRIMARY KEY column. SQLite stores that
    value as the cell's rowid and writes NULL in the record body.
    """
    tokens = [
        token.value
        for token in sqlparse.parse(create_sql)[0].flatten()
        if not token.is_whitespace
    ]
    try:
        cursor = tokens.index("(") + 1
    except ValueError as exc:
        raise ValueError(f"CREATE TABLE has no column list: {create_sql}") from exc

    # name, declared type, and whether this column itself says PRIMARY KEY.
    parsed: list[tuple[str, str, bool]] = []
    depth = 0
    name: str | None = None
    type_parts: list[str] = []
    is_primary_key = False
    past_type = False
    skipping_constraint = False
    # A single-column table PRIMARY KEY (id) is also a rowid alias when id is INTEGER.
    collecting_pk = False
    pk_names: list[str] = []
    table_pk: list[str] = []

    def finish() -> None:
        nonlocal name, type_parts, is_primary_key, past_type, skipping_constraint
        nonlocal collecting_pk
        if name is not None:
            parsed.append((name, " ".join(type_parts).lower(), is_primary_key))
        name = None
        type_parts = []
        is_primary_key = False
        past_type = False
        skipping_constraint = False
        collecting_pk = False

    for token in tokens[cursor:]:
        if token == "(":
            depth += 1
            continue
        if token == ")":
            if depth == 0:
                finish()
                break
            depth -= 1
            if collecting_pk and depth == 0 and len(pk_names) == 1:
                table_pk = pk_names
            continue
        if depth:
            if collecting_pk and depth == 1 and token.upper() not in {",", "ASC", "DESC"}:
                pk_names.append(unquote_identifier(token))
            continue
        if token == ",":
            finish()
            continue

        upper = token.upper()
        if name is None:
            if upper in {"PRIMARY", "PRIMARY KEY"}:
                skipping_constraint = True
                collecting_pk = True
                pk_names = []
            elif upper in TABLE_CONSTRAINTS:
                skipping_constraint = True
            elif not skipping_constraint:
                name = unquote_identifier(token)
            continue
        if upper in COLUMN_CONSTRAINTS:
            past_type = True
            if upper in {"PRIMARY", "PRIMARY KEY"}:
                is_primary_key = True
            continue
        if not past_type:
            type_parts.append(token)
    else:
        finish()

    table_pk_name = table_pk[0].lower() if len(table_pk) == 1 else None
    columns: list[tuple[str, bool]] = []
    for column_name, declared_type, column_is_primary_key in parsed:
        is_rowid = declared_type == "integer" and (
            column_is_primary_key or column_name.lower() == table_pk_name
        )
        columns.append((column_name, is_rowid))
    return columns


def usable_page_size(database: bytes) -> int:
    """Page size minus the reserved bytes at the end of every page."""
    return page_size(database) - database[20]


def payload_local_size(payload_size: int, usable: int, max_local: int) -> int:
    """Bytes of a cell payload stored on the b-tree page itself.

    Anything past this spills onto overflow pages. `max_local` is U-35 for a
    table leaf and ((U-12)*64/255)-23 for an index page. U is the usable size.
    """
    if payload_size <= max_local:
        return payload_size
    min_local = ((usable - 12) * 32 // 255) - 23
    local = min_local + ((payload_size - min_local) % (usable - 4))
    if local <= max_local:
        return local
    return min_local


def table_leaf_max_local(usable: int) -> int:
    """Largest table-leaf payload stored on the page with no overflow."""
    return usable - 35


def index_max_local(usable: int) -> int:
    """Largest index payload stored on the page with no overflow."""
    return ((usable - 12) * 64 // 255) - 23


def read_overflow(
    database: bytes,
    page_number: int,
    remaining: int,
    page_size_bytes: int,
    usable: int,
) -> bytes:
    """Payload bytes stored on the overflow-page chain starting at page_number."""
    chunks = []
    while remaining > 0 and page_number != 0:
        page_start = (page_number - 1) * page_size_bytes
        page_number = int.from_bytes(database[page_start : page_start + 4], byteorder="big")
        take = min(remaining, usable - 4)
        chunks.append(database[page_start + 4 : page_start + 4 + take])
        remaining -= take
    return b"".join(chunks)


def locate_payload(
    database: bytes,
    cursor: int,
    payload_size: int,
    usable: int,
    page_size_bytes: int,
    max_local: int,
):
    """Buffer and offset where a cell payload starts.

    The payload is read in place when it fits on the page. When it overflows,
    the page-local prefix and the overflow chain are joined into one buffer.
    """
    local = payload_local_size(payload_size, usable, max_local)
    if local == payload_size:
        return database, cursor
    payload = bytearray(database[cursor : cursor + local])
    overflow_page = int.from_bytes(
        database[cursor + local : cursor + local + 4], byteorder="big"
    )
    payload += read_overflow(
        database, overflow_page, payload_size - local, page_size_bytes, usable
    )
    return bytes(payload), 0


def read_table_leaf_record(
    database: bytes,
    cell_offset: int,
    encoding: str,
    usable: int,
    page_size_bytes: int,
    columns: set[int] | None = None,
) -> tuple[int, list]:
    """(rowid, record) from a table b-tree leaf cell."""
    payload_size, cursor = read_varint(database, cell_offset)
    rowid, cursor = read_varint(database, cursor)
    buffer, offset = locate_payload(
        database,
        cursor,
        payload_size,
        usable,
        page_size_bytes,
        table_leaf_max_local(usable),
    )
    return rowid, read_record(buffer, offset, encoding, columns)


def table_rows(database: bytes, page_number: int) -> Iterator[tuple[int, list]]:
    """(rowid, record) for every row in a table b-tree, in rowid order.

    An interior page stores no rows. Each of its cells names a left child, and
    a final right-child pointer covers the rest of the keys. A leaf page holds
    the rows. A payload that does not fit on the leaf continues on overflow pages.
    """
    page_size_bytes = page_size(database)
    encoding = text_encoding(database)
    usable = usable_page_size(database)

    def walk(number: int) -> Iterator[tuple[int, list]]:
        page_start = (number - 1) * page_size_bytes
        # Page 1 begins with the 100-byte database header; later pages do not.
        header = page_start + (SCHEMA_PAGE_HEADER_OFFSET if number == 1 else 0)
        page_type = database[header]
        cell_count = int.from_bytes(database[header + 3 : header + 5], byteorder="big")

        if page_type == INTERIOR_TABLE_PAGE_TYPE:
            array_start = header + INTERIOR_TABLE_HEADER_SIZE
            for index in range(cell_count):
                pointer = array_start + index * 2
                cell_offset = page_start + int.from_bytes(
                    database[pointer : pointer + 2], byteorder="big"
                )
                child = int.from_bytes(database[cell_offset : cell_offset + 4], byteorder="big")
                yield from walk(child)
            right_child = int.from_bytes(database[header + 8 : header + 12], byteorder="big")
            yield from walk(right_child)
            return

        if page_type != LEAF_TABLE_PAGE_TYPE:
            raise ValueError(f"page {number} is not a table b-tree page")

        array_start = header + LEAF_TABLE_HEADER_SIZE
        for index in range(cell_count):
            pointer = array_start + index * 2
            # Cell pointers are offsets from the start of the page.
            cell_offset = page_start + int.from_bytes(
                database[pointer : pointer + 2], byteorder="big"
            )
            yield read_table_leaf_record(
                database, cell_offset, encoding, usable, page_size_bytes
            )

    yield from walk(page_number)


def render_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode()
    return str(value)


def column_spec(columns: list[tuple[str, bool]], column_name: str) -> tuple[int, bool]:
    """(record index, is INTEGER PRIMARY KEY) for a column name."""
    wanted = column_name.lower()
    for index, (name, is_rowid) in enumerate(columns):
        if name.lower() == wanted:
            return index, is_rowid
    raise ValueError(f"no such column: {column_name}")


def column_value(rowid: int, record: list, column_index: int, is_rowid: bool):
    """Value of one column. INTEGER PRIMARY KEY lives in the cell rowid."""
    if is_rowid:
        return rowid
    if column_index < len(record):
        return record[column_index]
    return None


def compare_values(left, right) -> int:
    """SQLite record order: NULL, then numbers, then text, then blobs.

    Text uses BINARY collation, which for UTF-8 matches code-point order.
    """
    left_class = value_class(left)
    right_class = value_class(right)
    if left_class != right_class:
        return -1 if left_class < right_class else 1
    if left is None or left == right:
        return 0
    return -1 if left < right else 1


def value_class(value) -> int:
    if value is None:
        return 0
    if isinstance(value, int | float):
        return 1
    if isinstance(value, str):
        return 2
    if isinstance(value, bytes):
        return 3
    raise TypeError(f"unsupported record value: {value!r}")


def index_columns(create_sql: str) -> list[str]:
    """Indexed column names, in CREATE INDEX order."""
    tokens = [
        token.value
        for token in sqlparse.parse(create_sql)[0].flatten()
        if not token.is_whitespace
    ]
    try:
        cursor = tokens.index("(") + 1
    except ValueError:
        return []

    names = []
    while cursor < len(tokens) and tokens[cursor] != ")":
        token = tokens[cursor]
        upper = token.upper()
        if upper == ",":
            cursor += 1
            continue
        if upper in {"ASC", "DESC"}:
            cursor += 1
            continue
        if upper == "COLLATE":
            cursor += 2
            continue
        names.append(unquote_identifier(token))
        cursor += 1
    return names


def index_root_for_column(database: bytes, table_name: str, column_name: str) -> int | None:
    """Root page of an index whose first column is `column_name`."""
    encoding = text_encoding(database)
    wanted = column_name.lower()
    for cell_offset in schema_cell_offsets(database):
        row = read_leaf_cell(database, cell_offset, encoding)
        if row[SCHEMA_TYPE] != "index" or row[SCHEMA_TBL_NAME] != table_name:
            continue
        create_sql = row[SCHEMA_SQL]
        if not isinstance(create_sql, str):
            continue
        columns = index_columns(create_sql)
        if columns and columns[0].lower() == wanted:
            return row[SCHEMA_ROOTPAGE]
    return None


def matching_index_rowids(database: bytes, rootpage: int, target) -> Iterator[int]:
    """Rowids of index entries whose first column equals `target`.

    An index record is the indexed columns followed by the table rowid.
    Interior pages store real keys, not just separators: the left child of a
    cell holds keys lower than that cell, and the right-most child holds keys
    higher than the last cell. Cells on a page are already in key order, so
    a search descends only into the child that can still hold `target`.
    """
    page_size_bytes = page_size(database)
    encoding = text_encoding(database)
    usable = usable_page_size(database)
    max_local = index_max_local(usable)

    def read_key(cell_offset: int, interior: bool) -> tuple[int | None, list]:
        cursor = cell_offset
        child = None
        if interior:
            child = int.from_bytes(database[cell_offset : cell_offset + 4], byteorder="big")
            cursor = cell_offset + 4
        payload_size, cursor = read_varint(database, cursor)
        buffer, offset = locate_payload(
            database, cursor, payload_size, usable, page_size_bytes, max_local
        )
        return child, read_record(buffer, offset, encoding)

    def walk(number: int) -> Iterator[int]:
        page_start = (number - 1) * page_size_bytes
        header = page_start + (SCHEMA_PAGE_HEADER_OFFSET if number == 1 else 0)
        page_type = database[header]
        cell_count = int.from_bytes(database[header + 3 : header + 5], byteorder="big")
        interior = page_type == INTERIOR_INDEX_PAGE_TYPE
        if interior:
            header_size = INTERIOR_TABLE_HEADER_SIZE
            right_child = int.from_bytes(database[header + 8 : header + 12], byteorder="big")
        elif page_type == LEAF_INDEX_PAGE_TYPE:
            header_size = LEAF_TABLE_HEADER_SIZE
            right_child = None
        else:
            raise ValueError(f"page {number} is not an index b-tree page")

        array = header + header_size
        for index in range(cell_count):
            pointer = array + index * 2
            cell_offset = page_start + int.from_bytes(
                database[pointer : pointer + 2], byteorder="big"
            )
            child, record = read_key(cell_offset, interior)
            compared = compare_values(record[0], target)
            if interior:
                if compared > 0:
                    yield from walk(child)
                    return
                if compared == 0:
                    yield from walk(child)
                    yield record[-1]
            elif compared == 0:
                yield record[-1]
            elif compared > 0:
                return
        if right_child is not None:
            yield from walk(right_child)

    yield from walk(rootpage)


def table_records(
    database: bytes,
    rootpage: int,
    rowids: Iterator[int],
    columns: set[int] | None = None,
) -> Iterator[tuple[int, list]]:
    """Records for an ascending sequence of rowids.

    An interior cell's rowid is the largest rowid in its left subtree, and the
    row itself lives on a leaf. Divider keys are cached. Cells on a leaf are
    ordered, so the first requested rowid is found with a binary search and
    the following ones are the cells after it.
    """
    page_size_bytes = page_size(database)
    encoding = text_encoding(database)
    usable = usable_page_size(database)
    interiors: dict[int, tuple[list[int], list[int], int]] = {}
    leaves: dict[int, tuple[list[int], list[int]]] = {}

    def load_leaf(page_start: int, array: int, cell_count: int) -> tuple[list[int], list[int]]:
        rowid_list = []
        offsets = []
        for index in range(cell_count):
            pointer = array + index * 2
            cell_offset = page_start + int.from_bytes(
                database[pointer : pointer + 2], byteorder="big"
            )
            _, cursor = read_varint(database, cell_offset)
            rowid, _ = read_varint(database, cursor)
            rowid_list.append(rowid)
            offsets.append(cell_offset)
        return rowid_list, offsets

    def descend(target: int) -> int:
        number = rootpage
        while True:
            cached = interiors.get(number)
            if cached is None and number not in leaves:
                page_start = (number - 1) * page_size_bytes
                header = page_start + (SCHEMA_PAGE_HEADER_OFFSET if number == 1 else 0)
                page_type = database[header]
                cell_count = int.from_bytes(database[header + 3 : header + 5], byteorder="big")
                if page_type == LEAF_TABLE_PAGE_TYPE:
                    leaves[number] = load_leaf(
                        page_start, header + LEAF_TABLE_HEADER_SIZE, cell_count
                    )
                    return number
                if page_type != INTERIOR_TABLE_PAGE_TYPE:
                    raise ValueError(f"page {number} is not a table b-tree page")
                array = header + INTERIOR_TABLE_HEADER_SIZE
                right = int.from_bytes(database[header + 8 : header + 12], byteorder="big")
                keys = []
                children = []
                for index in range(cell_count):
                    pointer = array + index * 2
                    cell_offset = page_start + int.from_bytes(
                        database[pointer : pointer + 2], byteorder="big"
                    )
                    child = int.from_bytes(
                        database[cell_offset : cell_offset + 4], byteorder="big"
                    )
                    key, _ = read_varint(database, cell_offset + 4)
                    children.append(child)
                    keys.append(key)
                cached = (keys, children, right)
                interiors[number] = cached
            if number in leaves:
                return number
            keys, children, right = cached
            index = bisect.bisect_left(keys, target)
            number = right if index == len(keys) else children[index]

    pending = iter(rowids)
    try:
        target = next(pending)
    except StopIteration:
        return

    previous = None
    while True:
        number = descend(target)
        if number == previous:
            raise ValueError(f"indexed rowid {target} is not in the table")
        previous = number
        rowid_list, offsets = leaves[number]
        start = 0
        while rowid_list and target <= rowid_list[-1]:
            index = bisect.bisect_left(rowid_list, target, start)
            if index == len(rowid_list) or rowid_list[index] != target:
                raise ValueError(f"indexed rowid {target} is not in the table")
            _, record = read_table_leaf_record(
                database, offsets[index], encoding, usable, page_size_bytes, columns
            )
            yield target, record
            start = index + 1
            try:
                target = next(pending)
            except StopIteration:
                return


def select_columns(
    database: bytes,
    table_name: str,
    column_names: list[str],
    where: tuple[str, object] | None = None,
) -> list[str]:
    """One line per row. Multiple columns are joined with '|', in SELECT order.

    `where` is (column, literal) from `column = literal`. When an index starts
    with that column, matching rowids come from the index and each row is
    fetched by rowid. Otherwise the filter is a scan of the table b-tree.
    """
    rootpage, create_sql = table_definition(database, table_name)
    columns = table_columns(create_sql)
    specs = [column_spec(columns, name) for name in column_names]
    filter_spec = column_spec(columns, where[0]) if where is not None else None
    filter_value = where[1] if where is not None else None

    if where is not None:
        index_root = index_root_for_column(database, table_name, where[0])
        if index_root is not None:
            needed = {index for index, is_rowid in specs if not is_rowid}
            lines = []
            rowids = matching_index_rowids(database, index_root, filter_value)
            for rowid, record in table_records(database, rootpage, rowids, needed):
                values = [
                    render_value(column_value(rowid, record, column_index, is_rowid))
                    for column_index, is_rowid in specs
                ]
                lines.append("|".join(values))
            return lines

    lines = []
    for rowid, record in table_rows(database, rootpage):
        if filter_spec is not None:
            # NULL never equals a literal, including another NULL.
            cell = column_value(rowid, record, *filter_spec)
            if cell is None or cell != filter_value:
                continue
        values = [
            render_value(column_value(rowid, record, column_index, is_rowid))
            for column_index, is_rowid in specs
        ]
        lines.append("|".join(values))
    return lines


def sql_literal(token) -> object:
    """Python value of a SQLite literal token."""
    if token.ttype is sqlparse.tokens.Literal.String.Single:
        # Single quotes wrap the text. A quote inside the text is written ''.
        return token.value[1:-1].replace("''", "'")
    if token.ttype is sqlparse.tokens.Literal.Number.Integer:
        return int(token.value)
    raise ValueError(f"unsupported literal: {token.value}")


def parse_where(where: Where) -> tuple[str, object] | None:
    """(column, literal) from `WHERE column = literal`, or None if not that shape."""
    comparison = next(
        (token for token in where.tokens if isinstance(token, Comparison)), None
    )
    if comparison is None:
        return None

    column = None
    operator = None
    literal = None
    for token in comparison.tokens:
        if token.is_whitespace:
            continue
        if isinstance(token, Identifier) and column is None:
            column = unquote_identifier(token.get_real_name())
        elif token.ttype is sqlparse.tokens.Operator.Comparison and operator is None:
            operator = token.value
        elif literal is None and token.ttype in {
            sqlparse.tokens.Literal.String.Single,
            sqlparse.tokens.Literal.Number.Integer,
        }:
            literal = sql_literal(token)
        else:
            return None
    if column is None or operator != "=" or literal is None:
        return None
    return column, literal


def parse_select(
    command: str,
) -> tuple[list[str], str, tuple[str, object] | None] | None:
    """SELECT col [, col ...] FROM table [WHERE col = literal].

    Returns (columns, table, filter). filter is None when there is no WHERE.
    Returns None when the statement is not that shape.
    """
    statement = sqlparse.parse(command)[0]
    if statement.get_type() != "SELECT":
        return None

    column_names: list[str] = []
    table_name = None
    where_filter = None
    for token in statement.tokens:
        if token.is_whitespace or token.ttype is sqlparse.tokens.Keyword.DML:
            continue
        if token.ttype is sqlparse.tokens.Keyword and token.normalized == "FROM":
            continue
        if isinstance(token, IdentifierList):
            column_names = [
                unquote_identifier(
                    identifier.get_real_name()
                    if isinstance(identifier, Identifier)
                    else identifier.value
                )
                for identifier in token.get_identifiers()
            ]
        elif isinstance(token, Identifier):
            name = unquote_identifier(token.get_real_name())
            if not column_names:
                column_names = [name]
            elif table_name is None:
                table_name = name
            else:
                return None
        elif isinstance(token, Where):
            where_filter = parse_where(token)
            if where_filter is None:
                return None
        else:
            return None

    if not column_names or table_name is None:
        return None
    return column_names, table_name, where_filter


def main() -> None:
    database_file_path = sys.argv[1]
    command = sys.argv[2]

    # Map the file instead of reading it. The index-scan test uses a ~1GB
    # database and only a few pages are touched for each query.
    with open(database_file_path, "rb") as database_file:
        database = mmap.mmap(database_file.fileno(), 0, access=mmap.ACCESS_READ)

    if command == ".dbinfo":
        # Stage 1: database page size is a 2-byte big-endian value
        # immediately after the 16-byte magic string.
        # Stage 2: sqlite_schema lives on page 1. The 100-byte file header
        # is part of that page, and the b-tree page header follows it.
        # Cell count is a 2-byte big-endian integer at page-header offset 3.
        # Each cell is one schema row, and this stage only has tables.
        print(f"database page size: {page_size(database)}")
        print(f"number of tables: {page_cell_count(database, 1)}")
    elif command == ".tables":
        # Stage 3: user table names live in sqlite_schema.tbl_name.
        # The cell pointer array follows the page header; each entry is a
        # 2-byte big-endian offset to a table b-tree leaf cell. A cell is a
        # payload-size varint, a rowid varint, and a record. The record's
        # third column is tbl_name. Skip sqlite_* tables, same as SQLite.
        print(" ".join(user_table_names(database)))
    elif command.upper().startswith("SELECT COUNT(*)"):
        # Stage 4: the last token is the table name. Its sqlite_schema row
        # stores the root page, and that page's cell count is the row count
        # while the table still fits on a single leaf page.
        table_name = command.split(" ")[-1]
        print(page_cell_count(database, table_rootpage(database, table_name)))
    elif command.upper().startswith("SELECT"):
        # Stages 5–9: records store columns in CREATE TABLE order. That
        # statement is the sql column of the table's sqlite_schema row. An
        # INTEGER PRIMARY KEY is the cell rowid; the record body holds NULL
        # for it. Several columns are printed on one line, separated by '|'.
        # WHERE column = literal keeps matching rows. If an index starts with
        # that column, the search follows the index b-tree and then fetches
        # each row by rowid. Otherwise a large table's root is an interior
        # page whose cells point at child pages, and the scan walks the whole
        # table b-tree down to the leaves.
        parsed = parse_select(command)
        if parsed is None:
            print(f"Invalid command: {command}")
        else:
            column_names, table_name, where = parsed
            for line in select_columns(database, table_name, column_names, where):
                print(line)
    else:
        print(f"Invalid command: {command}")
    database.close()


if __name__ == "__main__":
    main()
