"""A simple wrapper for sqlite3

Removes some of the following annoying tasks of managing sqlite3 development:
 * Creating your own SQL statements
 * Managing where to store the db file
 * Error handling
 * Error logging
 * Managing where to store your log file
 * Argument parameterization and type-checking

Reserved table names that are included in all databases created by this wrapper:
 * tbl_pySQLiteR_DB_VERSION (version:INTEGER, date_created:INTEGER)
 * tbl_pySQLiteR_VERSION (version:TEXT)

Todos:
    * Remove unused functions / commented out code
    * Add to PyPI once API is sufficiently stable (v1.0.0)
"""

# Standard Python Library 2.7
import sqlite3
import os
import logging
from warnings import warn
import sys
import inspect
import re

# PyPI modules
import appdirs #appdirs
from enum import Enum #enum34

# pylint: disable=R0903

ENALBE_DEBUG_PRINT = False

#version of pySQLiteR
TBL_PYSQLITER_VERSION = 'v0.0.2'
TBL_PYSQLITER_URL = 'https://github.com/kristovatlas/PySQLiteR'
#table to store db info
DB_VERSION_TBL_NAME = 'tbl_pySQLiteR_DB_VERSION'
#table to store pySQLiteR info
PYSQLITER_VERSION_TBL_NAME = 'tbl_pySQLiteR_VERSION'

SQL_TYPE_TO_PYTHON = {'TEXT': str,
                      'INTEGER': int}

class Reserved(Enum):
    """Special SQL keywords"""
    ARG_PLACEHOLDER = '?'
    CURRENT_TIMESTAMP = 'CURRENT_TIMESTAMP'

DB_SELECT_RETURNED_NULL_MSG = 'Received null value instead of row.'

class DatabaseWriteError(Exception):
    """There was a problem writing to the database."""
    pass

class DatabaseReadError(Exception):
    """There was a problem reading from the database."""
    pass

class SQLRawExpression(object):
    """A raw SQL expression consisting of a string that will not be validated
    Use carefully, or you may introduce SQL injection vulnerabilities.
    """
    def __init__(self, expr):
        assert isinstance(expr, str)
        self.expr = expr

class SQLExpression(object):
    """An expression including a subset of SQLite operators and operands"""

    def __str__(self):
        raise NotImplementedError

    def __repr__(self):
        self.__str__()

class ComparisonExpression(SQLExpression):
    """SQLite binary comparison operators and operands, e.g. col_name > value

    Args:
        col (str): The name of a valid column in the table a WHERE clause
            corresponds to.
        val: The data value compared to. It may not be a column name.
    """
    def __init__(self, col, val, op_str=None):
        super(ComparisonExpression, self).__init__()
        assert isinstance(col, str)
        self.col = col
        self.val = val
        self.op_str = op_str

    def __str__(self):
        return '{0} {1} {2}'.format(self.col, self.op_str, self.val)

class Equals(ComparisonExpression):
    """SQLite col_name = value"""
    def __init__(self, col, val):
        super(Equals, self).__init__(col, val, op_str='=')

class NotEquals(ComparisonExpression):
    """SQLite col_name != value"""
    def __init__(self, col, val):
        super(NotEquals, self).__init__(col, val, op_str='!=')

class LessThan(ComparisonExpression):
    """SQLite col_name < value"""
    def __init__(self, col, val):
        super(LessThan, self).__init__(col, val, op_str='<')

class LessThanEquals(ComparisonExpression):
    """SQLite col_name <= value"""
    def __init__(self, col, val):
        super(LessThanEquals, self).__init__(col, val, op_str='<=')

class LogicalExpression(SQLExpression):
    """SQLite logical operator and operands, e.g. AND"""
    def __str__(self):
        raise NotImplementedError

class UnaryLogicalExpression(LogicalExpression):
    """SQLite unary logical operator and operands, e.g. TODO

    TODO: Implement with a class field called op
    """
    def __init__(self):
        super(UnaryLogicalExpression, self).__init__()
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError

class BinaryLogicalExpression(LogicalExpression):
    """SQLite binary logical operator and operands, e.g. expr AND expr

    A variable-length argument is used to support conjoining more than 2
    operands for flexibility, even though they are technically binary
    operators.
    """
    def __init__(self, *args):
        dprint("sqliter: BinaryLogicalExpression: %s" %
               str([str(x) for x in args]))
        for expression in args:
            assert isinstance(expression, SQLExpression)
        self.ops = args
        self.op_str = None

        super(BinaryLogicalExpression, self).__init__()

    def __str__(self):
        _str = ' ('
        _str += ' {0} '.format(self.op_str).join([str(x) for x in self.ops])
        _str += ') '
        return _str

    def __repr__(self):
        return self.__str__()

class And(BinaryLogicalExpression):
    """SQLite 'AND' operator and operands

    A variable-length argument is used to support conjoining more than 2
    operands for flexibility, even though AND is technically a binary
    operator.
    """
    def __init__(self, *args):
        assert len(args) > 1, \
            "Expected 2 or more operands as args since And is a binary operator"

        dprint("sqliter: And: types of args: %s" %
               str([type(x) for x in args]))
        dprint("sqliter: And: %s" % str([str(x) for x in args]))
        super(And, self).__init__(*args)
        self.op_str = 'AND'

    def __repr__(self):
        return self.__str__()

class WhereComponent(object):
    """Contains an expression in a WHERE clause and relevant state

    Args:
        db_table (DatabaseTable): The db table that this WHERE clause relates to
        expr (SQLExpression): The expression being encapsulated by this object
        arglist (list): A list of values being built as the WHERE clause's
            components are visited
        where (Where): The object encapsulating the WHERE clause that this
            is a component of.

    """
    def __init__(self, db_table, expr, arglist, where):
        assert isinstance(db_table, DatabaseTable)
        assert isinstance(expr, SQLExpression)
        assert isinstance(arglist, list)
        self.db_table = db_table
        self.expr = expr
        self.arglist = arglist
        self.where = where

class Where(object):
    """Represents a WHERE clause, building a parameterized arglist if needed.

    The WHERE clause is a boolean expression comprised of either:
    * a single comparison expression e.g. 'myrow > 5', or
    * an expression containing a logical operator combining multiple comparisons
        of arbitrary depth, e.g. '(myrow > 5 AND myrow < 10)'

    Args:
        db_table (DatabaseTable): The database table to which this WHERE clause
            corresponds
        limit (Optional[int]): If specified, only this many records will be
            included.
    """
    def __init__(self, db_table, limit=None):
        assert isinstance(db_table, DatabaseTable)
        assert limit is None or isinstance(limit, int)

        self.db_table = db_table
        self.limit = limit
        self.root = None #set to top-most SQLExpression
        self.arglist = []

    def __str__(self):
        if self.root is None:
            raise ValueError("No expressions added to where clause yet.")

        _str = ' WHERE {0}'.format(str(self.root))
        if self.limit is not None:
            _str = '{0} LIMIT {1}'.format(_str, self.limit)
        return remove_repeat_spaces(_str)

    def __repr__(self):
        return self.__str__()

    def and_(self, *args):
        """Constructs an AND expression with two or more expressions as operands

        Args:
            *args: Variable-length argument tuple consisting of `WhereComponent`
                objects, each of which is an operand to the AND operator.

        Returns: `WhereComponent` encapsulating the AND expression constructed
        """
        for arg in args:
            assert isinstance(arg, WhereComponent)

        dprint("sqliter: and_: exprs = " + str([str(x) for x in args]))
        exprs = _get_exprs(*args)
        assert len(exprs) == len(args)

        dprint("sqliter: and_: exprs types = " + str([type(x) for x in exprs]))
        for expression in exprs:
            assert isinstance(expression, SQLExpression)

        and_op = And(*exprs)

        #aggregate arglist from child expressions
        arglist = []
        for index, expression in enumerate(exprs):
            operand_where_component = args[index]
            arglist = arglist + operand_where_component.arglist

        where_component = WhereComponent(
            db_table=self.db_table, expr=and_op, arglist=arglist, where=self)
        return where_component

    def build_comparison(self, col, val, operator_class):
        """Perform actions related to building a generic binary comparison expr

        Args:
            col (str): Name of table column being compared to
            val: The value being compared to
            operator_class (ComparisonExpression): The comparison operator

        Returns:
            WhereComponent: An encapsulation of the expression constructed
        """
        dprint("sqliter: build_comparison: col = %s val = %s" % (col, str(val)))
        assert isinstance(col, str)
        assert not isinstance(val, SQLExpression)
        assert is_subclass(operator_class, ComparisonExpression)
        assert self.db_table.is_valid_col(col)

        resolved_val, arglist = parameterize_val(val)
        expr = operator_class(col, resolved_val)

        where_component = WhereComponent(
            db_table=self.db_table, expr=expr, arglist=arglist, where=self)

        return where_component

    def eq(self, col, val):
        """Assert col value = val

        Returns:
            `WhereComponent`: encapulsating the equality expression constructed
        """
        dprint("sqliter: eq: col = %s val = %s" % (col, str(val)))
        return self.build_comparison(col=col, val=val, operator_class=Equals)

    def lt(self, col, val):
        """Assert col value < val

        Returns:
            `WhereComponent`: encapsulating the less-than expression constructed
        """
        return self.build_comparison(col=col, val=val, operator_class=LessThan)

    def lte(self, col, val):
        """Assert col value <= val

        Returns:
            `WhereComponent`: encapsulating the less-than-or-equals expression
                constructed
        """
        return self.build_comparison(
            col=col, val=val, operator_class=LessThanEquals)

class DatabaseTable(object):
    """Represents a table in the database"""
    def __init__(self):
        self.name = ''
        self.cols = tuple() # ((col_name1, col_type1), (col_name2, col_type2)..)
        self.col_names = []

    def set_cols(self, col_tuple):
        """Set the columns that represent the schema for this table

        Args:
            col_tuple (tuple(pair)): An n-tuple of 2-tuples, each 2-tuple
                a string representation of the column name and SQL type
        """
        dprint("sqliter: set_cols entered with %d cols" % len(col_tuple))
        self.cols = col_tuple
        dprint("sqliter: set_cols set cols to %s" % str(self.cols))
        self.col_names = [col[0] for col in self.cols]
        dprint("sqliter: set_cols col_names are: %s" % str(self.col_names))

    def get_create_statement(self):
        """Generate SQL statement to create this table"""
        assert isinstance(self.cols, tuple)
        stmt = 'CREATE TABLE {0} ('.format(self.name)

        name_type_pairs = ["{n} {t}".format(n=n, t=t) for n, t in self.cols]
        stmt += ','.join(name_type_pairs)
        stmt += ')'
        return stmt

    def get_insert_statement(self, col_res_map):
        """Generate SQL statement to insert a row into this table.

        Args:
            col_res_map (dict str=>val): Mapping col names to `Reserved` values
                that will be included in the INSERT statement, which are either
                placeholders ('?') or SQL keywords like CURRENT_TIMESTAMP.
                Example: {'myInt': Reserved.ARG_PLACEHOLDER,
                          'curtime': Reserved.CURRENT_TIMESTAMP}
        """
        col_str = ''
        val_str = ''

        num_cols_processed = 0
        num_cols_total = len(col_res_map)

        for col_name in col_res_map:
            res_value = col_res_map[col_name]
            assert isinstance(col_name, str)
            assert isinstance(res_value, Reserved)
            assert col_name in self.col_names

            col_str = ''.join([col_str, col_name])
            val_str = ''.join([val_str, res_value.value])
            num_cols_processed += 1

            if num_cols_processed < num_cols_total:
                col_str = ''.join([col_str, ', '])
                val_str = ''.join([val_str, ', '])

        stmt = 'INSERT INTO {0} ({1}) VALUES ({2})'.format(
            self.name, col_str, val_str)
        return stmt

    def check_types(self, col_val_map):
        """Warn if any values inserted do not appear to match the col's SQL type
        """
        for col_name in col_val_map:
            val = col_val_map[col_name]
            #find the col defn for this col containing SQL type and SQL constraints
            python_type = None

            for table_col in self.cols:
                table_col_name = table_col[0]
                table_col_defn = table_col[1]

                if col_name == table_col_name:
                    #found the col defn
                    for sql_type in SQL_TYPE_TO_PYTHON:
                        if sql_type in table_col_defn:
                            python_type = SQL_TYPE_TO_PYTHON[sql_type]
                            break
                    break

            if python_type is None:
                msg = ('Could not determine appropriate Python type for col '
                       'being inserted; type checking will not be applied.')
                warn(msg)

            #Don't bother type checking reserved values
            if isinstance(val, Reserved):
                continue

            if not isinstance(val, python_type):
                msg = ('Incompatible type being inserted. Expected {0}, saw '
                       '{1}.').format(python_type, type(val))
                warn(msg)

    def get_insert(self, col_val_map):
        """Generate SQL statement and arglist given list of values.

        Infers the SQL type based on the `cols` attribute of this class.

        Args:
            col_val_map (dict[str=>val]): col_val_map (dict): The values
                inserted corresponding to their columns. Values MAY be
                `Reserved` enums.

        Returns: (str, list): The INSERT statement and arglist
        """
        #Warn if any value doesn't seem to match column's SQL type
        dprint("sqliter: get_insert: col_val_map = %s" % str(col_val_map))
        self.check_types(col_val_map)

        #Go through map and build list of values and arglist for INSERT stmt
        col_res_map = dict()
        arglist = []
        for col_name in col_val_map:
            value = col_val_map[col_name]
            #attempt to resolve value to Reserved keyword
            if isinstance(value, Reserved):
                #inserting a reserved value that doesn't need to be parameterized
                col_res_map[col_name] = value
            else:
                #parameterized unsafe, non-reserved value
                col_res_map[col_name] = Reserved.ARG_PLACEHOLDER
                arglist.append(value)

        assert len(col_val_map) == len(col_res_map)

        stmt = self.get_insert_statement(col_res_map)
        return (stmt, arglist)

    def is_valid_col(self, col_name):
        """Does the col exist in this table?"""
        return col_name in self.col_names


class DatabaseConnection(object):
    """A connection to the database.
    Usage:
        with datastore.DatabaseConnection() as db_con:
            db_con.foo()
            ...

    API Functions:
        `insert`: Insert specfied values as row in a specific table
        `select`: Get a row represented as a dict (key by col name) with
            optional WHERE constraints
        `_eq`: A WHERE constraint requiring a column in the table to be equal
            to a specified value
        `check_db_version`: Get the database version of this database
    """

    def __init__(self, db_tables=None, app_tuple=None, filenames=None,
                 file_path_abs=False):
        """Note -- may be prone to a few TOCTOU issues related to the db flie if
        changed externally.

        Args:
            db_tables (Optional[List(DatabaseTable)]): A list of database tables
                specified for this application representing its schema. This
                MUST be specified if the database file is being initialized
                for the first time, as this is how the class finds out how to
                structure the database.
            app_name (Optional[tuple(str, str, int)]): If specified, contains
                the (application_name, applicatoin_author, database_version).
                The app name and author will determine the name of the database
                file connected to. Use of this setting will also designate that
                the database file shall be stored in the default application
                data directory. The database version denotes schema
                compatibility and will be stored in a special table called
                `tbl_pySQLiteR_DB_VERSION`.
            filenames (Optional[tuple(str, str)]): Absolute or relative
                filenames of the db file and log file, if not determined by the
                `app_tuple`
            file_path_abs (Optional[bool]): Determines whether filenames
                specified in `filenames` argument are interpretted as absolute
                or relative. If relative, files will be referenced with the
                default application data directory.

        Attributes:
            db_filepath (str): The absolute path of the database file in the
                filesystem
            log_filepath (str): The absolute path of the log file in the
                filesystem

        Raises: DatabaseReadError: If database version in sqlite file is not
            supported.
        """
        dprint("sqliter: Resolving filepaths...")
        #First, resolve filepaths for SQLite3 database file and log file
        db_version = None
        if app_tuple is not None:
            assert filenames is None
            assert not file_path_abs
            assert len(app_tuple) == 3
            assert isinstance(app_tuple[0], str)
            assert isinstance(app_tuple[1], str)
            assert isinstance(app_tuple[2], int)
            app_name = app_tuple[0]
            author = app_tuple[1]
            db_version = app_tuple[2]
            db_filename = app_name_to_db(app_name)
            self.db_filepath = get_app_file_loc(
                app_name=app_name, author=author, filename=db_filename)
            log_filename = app_name_to_log(app_name)
            self.log_filepath = get_app_file_loc(
                app_name=app_name, author=author, filename=log_filename)
        else:
            assert filenames is not None
            assert len(filenames) == 2
            assert isinstance(filenames[0], str)
            assert isinstance(filenames[1], str)

            if file_path_abs:
                self.db_filepath = filenames[0]
                self.log_filepath = filenames[1]
            else:
                #TODO: No obvious way to derive app data dir without app_name
                raise NotImplementedError

        assert isinstance(self.db_filepath, str)
        assert isinstance(self.log_filepath, str)

        dprint("sqliter: db_filepath: %s" % self.db_filepath)

        #Test log writeability
        if not os.path.isfile(self.log_filepath):
            touch(self.log_filepath)
        if not os.access(self.log_filepath, os.W_OK):
            warn("Unable to write to log file '{0}'".format(self.log_filepath))

        dprint("sqliter: log file must be writeable")

        #Try to connect to db
        if os.path.isfile(self.db_filepath):
            #TODO: handle unreadability and unwritability by logging
            self.conn = sqlite3.connect(self.db_filepath)
            if not os.access(self.db_filepath, os.W_OK):
                msg = 'Database file does not exist or is not writeable'
                self.log(msg, level=logging.ERROR)
                raise DatabaseReadError(msg)

            if os.stat(self.db_filepath).st_size == 0:
                if db_tables is None:
                    msg = ('Database file is uninitialized and no schema was '
                           'specified.')
                    self.log(msg, level=logging.ERROR)
                    raise DatabaseReadError(msg)

                self.table_init(db_tables=db_tables, db_version=db_version)
        else:
            self.log(msg="Database file does not exist. Initializing.",
                     level=logging.INFO)
            if db_tables is None:
                msg = ('Database file is uninitialized and no schema was '
                       'specified.')
                self.log(msg, level=logging.ERROR)
                raise DatabaseReadError(msg)
            self.conn = sqlite3.connect(self.db_filepath)
            self.table_init(db_tables=db_tables, db_version=db_version)

        # permit accessing results by col name
        self.conn.row_factory = sqlite3.Row

    def __enter__(self):
        return self

    def __exit__(self, exec_type, exec_value, exec_traceback):
        self.conn.close()

    def log(self, msg, level=logging.INFO, do_exit=False):
        """Add a string to the log file and optionally exit with error msg"""
        logging.basicConfig(filename=self.log_filepath,
                            format='%(asctime)s:%(levelname)s:%(message)s',
                            level=logging.INFO)
        if level == logging.DEBUG:
            logging.debug(msg)
        elif level == logging.INFO:
            logging.info(msg)
        elif level == logging.WARNING:
            logging.warning(msg)
        elif level == logging.ERROR:
            logging.error(msg)
        elif level == logging.CRITICAL:
            logging.critical(msg)
        else:
            raise ValueError(str(level))

        if do_exit:
            sys.exit(msg)

    def fetch(self, stmt, arglist=None, err_msg=None,
              err_log_level=logging.ERROR):
        """Fetch specified records

        Raises: DatabaseReadError
        """
        dprint("fetch: stmt = '%s', arglist = %s" % (stmt, arglist))
        if arglist is None:
            arglist = ()

        try:
            rows = self.conn.cursor().execute(stmt, arglist).fetchall()
            dprint("sqliter: fetch: Fetched %d rows" % len(rows))
            return rows
        except (sqlite3.OperationalError), err:
            msg = combine_err_msgs(err, err_msg)
            self.log(msg=msg, level=err_log_level)
            raise DatabaseReadError(msg)

    def fetch_one_row(self, stmt, arglist=None, err_msg=None,
                      err_log_level=logging.ERROR):
        """Fetch one row according to SQL select statement

        Returns: A row; never None

        Raises: DatabaseReadError
        """
        if arglist is None:
            arglist = ()

        try:
            row = self.conn.cursor().execute(stmt, arglist).fetchone()
            if row is not None:
                return row
            raise ValueError(DB_SELECT_RETURNED_NULL_MSG)
        except (sqlite3.OperationalError, ValueError), err:
            msg = combine_err_msgs(err, err_msg)
            self.log(msg=msg, level=err_log_level)
            raise DatabaseReadError(msg)

    def fetch_first_col(self, stmt, arglist=None, err_msg=None,
                        err_log_level=logging.ERROR):
        """Return the 0th item of the first row according to SQL select stmt

        Returns: A single variable or None if the value is NULL
        """
        try:
            return self.fetch_one_row(stmt, arglist, err_msg, err_log_level)[0]
        except (DatabaseReadError, IndexError), err:
            msg = combine_err_msgs(err, err_msg)
            self.log(msg=msg, level=err_log_level)
            raise DatabaseReadError(msg)

    def fetch_first_int(self, stmt, arglist=None, err_msg=None,
                        err_log_level=logging.ERROR):
        """Return the 0th integer item of the first row according SQL select stmt

        Returns: An integer; never None

        Raises: DatabaseReadError if unable to read from db or value is None
        """
        try:
            col = int(self.fetch_first_col(
                stmt, arglist, err_msg, err_log_level))
            if col is not None:
                return col
            raise ValueError("Value is NULL")
        except (DatabaseReadError, ValueError, TypeError), err:
            msg = combine_err_msgs(err, err_msg)
            self.log(msg=msg, level=err_log_level)
            raise DatabaseReadError(msg)

    def _create_table(self, stmt):
        """Execute CREATE TABLE statement

        Raises: DatabaseWriteError if table cannot be created
        """
        try:
            self.sql_execute(stmt)
        except sqlite3.OperationalError, err:
            msg = "Error creating table: {0}".format(err)
            self.log(msg=msg, level=logging.ERROR)
            raise DatabaseWriteError(msg)

    def table_init(self, db_tables, db_version=None):
        """Initialize database w/ required tables and return num of failures

        Args:
            db_tables (List[Databasetable]): A list of database tables used
                to initialize this database
            db_version (Optional[int]): If specified, this will be recorded
                with the time of creation of the database in a special table.

        Raises: DatabaseWriteError if database's tables cannot be initialized
        """
        dprint("sqliter: Entered table_init w/ %d app table(s)" % len(db_tables))
        pysqliter_ver_table = DatabaseTable()
        pysqliter_ver_table.name = PYSQLITER_VERSION_TBL_NAME
        pysqliter_ver_table.set_cols((('version', 'TEXT'), ('url', 'TEXT')))
        try:
            self._create_table(pysqliter_ver_table.get_create_statement())
        except DatabaseWriteError, err:
            msg = 'Error creating PySQLiteR version table: {0}'.format(err)
            self.log(msg, logging.CRITICAL)
            raise DatabaseWriteError(msg)

        try:
            pysqliter_version_record = {'version': TBL_PYSQLITER_VERSION,
                                        'url': TBL_PYSQLITER_URL}
            self.insert(db_table=pysqliter_ver_table,
                        col_val_map=pysqliter_version_record)
        except sqlite3.OperationalError, err:
            msg = "Error initializing PySQLiteR version table: {0}".format(err)
            self.log(msg, logging.CRITICAL)
            raise DatabaseWriteError(msg)

        if db_version is not None:
            assert isinstance(db_version, int)
            db_ver_table = DatabaseTable()
            db_ver_table.name = DB_VERSION_TBL_NAME
            db_ver_table.set_cols((('version', 'INTEGER'),
                                   ('date_created', 'INTEGER')))
            try:
                self._create_table(db_ver_table.get_create_statement())
            except DatabaseWriteError, err:
                self.log(str(err), logging.ERROR)
                raise DatabaseWriteError(str(err))

            try:
                init_record = {'version': db_version,
                               'date_created': Reserved.CURRENT_TIMESTAMP}
                self.insert(db_table=db_ver_table, col_val_map=init_record)
            except sqlite3.OperationalError, err:
                msg = "Error initializing db version table: {0}".format(err)
                self.log(msg, logging.ERROR)
                raise DatabaseWriteError(msg)

        for table in db_tables:
            stmt = table.get_create_statement()
            try:
                self._create_table(stmt)
            except DatabaseWriteError, err:
                msg = 'Error initializing application db table: {0}'.format(err)
                self.log(msg, logging.ERROR)
                raise DatabaseWriteError(msg)

    def sql_execute(self, stmt, arglist=None):
        """Execute the SQL statement and return number of db changes

        Raises: DatabaseWriteError if statement couldn't be executed

        Returns: int: Number of changes made executing the statement
        """
        dprint("sql_execute: stmt = '%s', arglist = %s" % (stmt, arglist))
        num_changes_previous = self.conn.total_changes
        try:
            if arglist is not None:
                self.conn.cursor().execute(stmt, arglist)
            else:
                self.conn.cursor().execute(stmt)
            self.conn.commit()
            num_changes = self.conn.total_changes - num_changes_previous
            dprint("sql_execute: %d changes made." % num_changes)
            return num_changes
        except sqlite3.OperationalError, err:
            msg = "Unable to execute statement: {0}: {1}".format(stmt, err)
            self.log(msg, logging.ERROR)
            raise DatabaseWriteError(msg)

    def check_db_version(self):
        """Get the version of this database

        Raises: DatabaseReadError if the version cannot be fetched
        """
        stmt = 'SELECT version FROM {0}'.format(DB_VERSION_TBL_NAME)
        try:
            return self.fetch_first_int(
                stmt,
                arglist=None,
                err_msg='Failed to select db version from table',
                err_log_level=logging.ERROR)
        except DatabaseReadError, err:
            msg = 'Error acquiring db version: {0}'.format(err)
            self.log(msg, level=logging.ERROR)
            raise DatabaseReadError(msg)

    def insert(self, db_table, col_val_map):
        """Insert specified values into database table

        Args:
            db_table (DatabaseTable): The table being inserted into
            col_val_map (dict): The values inserted. All values will be
                parameterized unless they are contained in the `Reserved` enum.
        """
        assert isinstance(db_table, DatabaseTable)
        stmt, arglist = db_table.get_insert(col_val_map)
        dprint("sqliter: insert: stmt = %s arglist = %s" % (stmt, str(arglist)))
        self.sql_execute(stmt, arglist)

    def select(self, col_names, **kwargs):
        """Select rows from database.

        You can either select all rows by specifying a `DatabaseTable`, or
        zero or more rows according to a WHERE clause by specifying a `Where`
        object

        Args:
            col_names (List[str]): A list of column names to select. If set to
                None, then all columns will be selected.
            db_table (Optional[DatabaseTable]): The table from which to select
                all rows and all cols, XOR
            where (Optional[WhereComponent]): The WHERE clause used to specify
                which rows are expected, built from the various expression
                components that make up the WHERE clause.

        SQL syntax: SELECT col1, col2, FROM table WHERE expression

        Todos:
            Maybe do some type checking on the values returned? SQLite is pretty
            relaxed on storing values, e.g. storing strings where ints go
        """
        #First, decide if fetching all rows from table or according to WHERE
        #clause.
        db_table, where_component = get_table_and_where_comp(**kwargs)

        #Build list of columns being selected
        assert isinstance(col_names, list) or col_names is None
        col_names_str = ''
        if col_names is None:
            col_names_str = '*'
        else:
            for idx, col_name in enumerate(col_names):
                assert db_table.is_valid_col(col_name)
                col_names_str = ''.join([col_names_str, col_name])
                if idx < len(col_names) - 1:
                    col_names_str = ''.join([col_names_str, ', '])

        #create SELECT statement and arglist
        stmt = 'SELECT {0} FROM {1}'.format(col_names_str, db_table.name)
        arglist = []
        if where_component is not None:
            #set this expression as the root expression of the WHERE clause
            where = where_component.where
            where.root = where_component.expr
            stmt = ''.join([stmt, ' ', str(where)])
            arglist = where_component.arglist

        #TODO if we want to check type of values returned, here's where to do it
        return self.fetch(stmt, arglist=arglist)

    def update(self, col_val_map, **kwargs):
        """UPDATE rows in database.

        You can either UPDATE all rows, or update some rows according to a
        WHERE clause by specifying a `WhereComponent` object.

        SQL syntax: UPDATE table SET col1=va1, col2=val2 WHERE expression

        Args:
            col_val_map (dict str=>val): A map of column names and values to
                update to
            db_table (Optional[DatabaseTable]): The table from which to select
                all rows and all cols, XOR
            where (Optional[WhereComponent]): The WHERE clause used to specify
                which rows are updated, built from the various expression
                components that make up the WHERE clause.

        Returns: bool: Whether any changes were made to database
        """
        db_table, where_component = get_table_and_where_comp(**kwargs)

        #build SET statement and arglist
        set_str = ''
        arglist = []
        assert isinstance(col_val_map, dict)
        num_cols_total = len(col_val_map)
        num_cols_added = 0
        for col in col_val_map:
            val = col_val_map[col]
            assert db_table.is_valid_col(col)

            #TODO: could do type checking on value compared to col type here.

            resolved_val, arglist_part = parameterize_val(val)
            arglist = arglist + arglist_part

            set_str = ''.join([set_str, "{0} = {1}".format(col, resolved_val)])
            num_cols_added += 1
            if num_cols_added < num_cols_total:
                set_str = ''.join([set_str, ', '])

        assert set_str != '', "SET statement missing in update()"

        stmt = "UPDATE {0} SET {1}".format(db_table.name, set_str)

        #build WHERE statement if applicable
        if where_component is not None:
            #set this expression as the root expression of the WHERE clause
            where = where_component.where
            where.root = where_component.expr
            stmt = ''.join([stmt, ' ', str(where)])
            arglist = arglist + where_component.arglist

        num_changes = self.sql_execute(stmt, arglist)
        if num_changes > 0:
            return True
        elif num_changes == 0:
            return False
        else:
            warn("Expected 0 or more changes from update(), saw {0}".format(
                num_changes))
            return False

# Global Functions

def get_app_file_loc(app_name, author, filename):
    """Get string repr of file path for specified filename in application's dir

    Args:
        app_name (str): The name of the application, consisting of
            filesystem-safe characters.
        author (str): The individual or organization that authored the app,
            consisting of filesystem-safe characters.
        filename (str): The name of a file you wish to place in the application's
            directory.

    Returns: (str, str): The application directory and the absolute path of
        the file inside the application directory.

    Side-effects: Creates directories corresponding to appropriate application
                  dir if needed. Does NOT create the specified file if it Does
                  not previously exist.
    """
    if ' ' in app_name:
        warn('sqliter.get_app_file_loc: The app_name specified contains '
             'spaces, which may not be filesystem-safe')
    if ' ' in author:
        warn('sqliter.get_app_file_loc: The author specified contains spaces, '
             'which may not be filesystem-safe')
    app_dir = appdirs.user_data_dir(app_name, author)
    if not os.path.isdir(app_dir):
        os.makedirs(app_dir)
    return os.path.join(app_dir, filename)

def app_name_to_db(app_name):
    """Turn the application name into a canonical db filename"""
    return ''.join([app_name, '.db'])

def app_name_to_log(app_name):
    """Turn the application name into a canonical log filename"""
    return ''.join([app_name, '.log'])

def touch(fname, times=None):
    """Touch the file"""
    with open(fname, 'a'):
        os.utime(fname, times)

def combine_err_msgs(err, err_msg):
    """Take the message from the specified err and concatenate err_msg"""
    assert isinstance(err, Exception)
    msg = str(err)
    if err_msg is not None:
        msg += " ({0})".format(err_msg)
    return msg
'''
def _and(*arg):
    """Generates SQL statement as str AND-ing two or more operands"""
    return ' (' + ' AND '.join(arg) + ') '

def _or(*arg):
    """Generates SQL statement as str OR-ing two or more operands"""
    return ' (' + ' OR '.join(arg) + ') '
'''

def xor(bool_a, bool_b):
    """Return exclusive-or of two bools"""
    return bool(bool_a) != bool(bool_b)

def _get_exprs(*args):
    """If expressions are `WhereComponent` objs, extract the SQLExpressions"""
    dprint("sqliter._get_exprs: exprs = " + str([str(x) for x in args]))
    ret_exprs = []
    for arg in args:
        if isinstance(arg, SQLExpression):
            ret_exprs.append(arg)
        elif isinstance(arg, WhereComponent):
            ret_exprs.append(arg.expr)
        else:
            dprint("%s %s"% (str(type(arg)), str(args)))
            raise TypeError()

    return tuple(ret_exprs)

def all_subclasses(cls):
    """Get all subclasses of class.
    Reference:
    http://stackoverflow.com/questions/3862310/how-can-i-find-all-subclasses-of-a-class-given-its-name#3862957
    """
    return cls.__subclasses__() + [g for s in cls.__subclasses__()
                                   for g in all_subclasses(s)]

def is_subclass(child_class, parent_class):
    """Maury Povich for classes"""
    return (inspect.isclass(child_class) and
            child_class in all_subclasses(parent_class))

def remove_repeat_spaces(_str):
    """Remove repeated spaces from string
    Reference:
    http://stackoverflow.com/questions/2077897/substitute-multiple-whitespace-with-single-whitespace-in-python
    """
    dprint("sqliter: remove_repeat_spaces: %s" % _str)
    return re.sub(r'\s+', ' ', _str).strip()

def get_table_and_where_comp(**kwargs):
    """Helper function for DatbaseConnection.select(), update(), etc.

    Returns:
        (DatabaseTable, WhereComponent or None)
    """
    db_table = None
    where_component = None
    assert xor('db_table' in kwargs, 'where' in kwargs)
    for arg_name in kwargs:
        if arg_name == 'db_table':
            db_table = kwargs['db_table']
        elif arg_name == 'where':
            where_component = kwargs['where']
            assert isinstance(where_component, WhereComponent)
            db_table = where_component.db_table
        else:
            raise ValueError(
                "Invalid argument {0} to get_table_and_where_comp()".format(
                    arg_name))
    assert isinstance(db_table, DatabaseTable)
    return (db_table, where_component)

def parameterize_val(val):
    """Given a value, determine if it needs to be parameterized and gen arglist.

    Returns:
        (value, list): The value and arglist generated. If parameterized, value
            is set to Reserved.ARG_PLACEHOLDER and val is pushed to arglist.
    """
    arglist = []
    resolved_val = None
    try:
        Reserved(val)
        #value is a reserved keyword, don't parameterize
        resolved_val = val.value
    except ValueError:
        #val is not a reserved keyword

        if isinstance(val, SQLRawExpression):
            warn(("Including raw SQL expression that may create injection "
                  "vulnerabilities: '{0}'").format(val.expr))
            resolved_val = val.expr
        else:
            #Not reserved, nor a raw express; parameterize
            arglist = [val]
            resolved_val = Reserved.ARG_PLACEHOLDER.value

    return (resolved_val, arglist)

def dprint(msg):
    """Print debug statement to stdout"""
    if ENALBE_DEBUG_PRINT:
        print "DEBUG: {0}".format(str(msg))
