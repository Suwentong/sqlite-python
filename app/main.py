import struct
import sys

import sqlparse
from sqlparse.sql import Comparison, Identifier, IdentifierList, Where

# Page 1 is the sqlite_schema table. The 100-byte database header occupies
# the start of that page, and the 8-byte leaf table b-tree header follows it.
SCHEMA_PAGE_HEADER_OFFSET = 100
LEAF_TABLE_HEADER_SIZE = 8
LEAF_TABLE_PAGE_TYPE = 0x0D

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


def leaf_table_rows(database: bytes, page_number: int) -> list[tuple[int, list]]:
    """(rowid, record) for every cell on a leaf table page."""
    page_size_bytes = page_size(database)
    page_start = (page_number - 1) * page_size_bytes
    # Page 1 begins with the 100-byte database header; later pages do not.
    header = page_start + (SCHEMA_PAGE_HEADER_OFFSET if page_number == 1 else 0)
    if database[header] != LEAF_TABLE_PAGE_TYPE:
        raise ValueError(f"page {page_number} is not a leaf table page")

    cell_count = int.from_bytes(database[header + 3 : header + 5], byteorder="big")
    array_start = header + LEAF_TABLE_HEADER_SIZE
    encoding = text_encoding(database)
    rows = []
    for index in range(cell_count):
        pointer = array_start + index * 2
        # Cell pointers are offsets from the start of the page.
        cell_offset = page_start + int.from_bytes(
            database[pointer : pointer + 2], byteorder="big"
        )
        _, cursor = read_varint(database, cell_offset)
        rowid, cursor = read_varint(database, cursor)
        rows.append((rowid, read_record(database, cursor, encoding)))
    return rows


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


def select_columns(
    database: bytes,
    table_name: str,
    column_names: list[str],
    where: tuple[str, object] | None = None,
) -> list[str]:
    """One line per row. Multiple columns are joined with '|', in SELECT order.

    `where` is (column, literal) from `column = literal`. The table still fits
    on its root page, so the filter is a scan of that page.
    """
    rootpage, create_sql = table_definition(database, table_name)
    columns = table_columns(create_sql)
    specs = [column_spec(columns, name) for name in column_names]
    filter_spec = column_spec(columns, where[0]) if where is not None else None
    filter_value = where[1] if where is not None else None

    lines = []
    for rowid, record in leaf_table_rows(database, rootpage):
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
                unquote_identifier(identifier.get_real_name())
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

    with open(database_file_path, "rb") as database_file:
        database = database_file.read()

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
        # Stages 5–7: records store columns in CREATE TABLE order. That
        # statement is the sql column of the table's sqlite_schema row. An
        # INTEGER PRIMARY KEY is the cell rowid; the record body holds NULL
        # for it. Several columns are printed on one line, separated by '|'.
        # WHERE column = literal keeps matching rows. The table still fits
        # on its root page, so this is a scan of that page.
        parsed = parse_select(command)
        if parsed is None:
            print(f"Invalid command: {command}")
        else:
            column_names, table_name, where = parsed
            for line in select_columns(database, table_name, column_names, where):
                print(line)
    else:
        print(f"Invalid command: {command}")


if __name__ == "__main__":
    main()
