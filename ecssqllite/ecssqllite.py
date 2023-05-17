"""
DELL Object Service Provisioning - SQL Lite RDBMS
"""
import sqlite3

# Constants
MODULE_NAME = "sqllite"                  # Module Name


class SQLLiteException(Exception):
    pass


class SQLLiteUtility(object):
    """
    Stores ECS Authentication Information
    """
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def open_sqllite_db(self, name):
        """
        Checks if a database exists and create if it doesn't
        """
        try:
            """
            This command will open a connection to the database creating it along the way if it doesn't exist
            """
            sqllite_db = sqlite3.connect(name + '.db')

            self.logger.debug(MODULE_NAME + '::open_sqllite_db()::Database ' + name + ' opened.')
            return sqllite_db

        except Exception as e:
            self.logger.error(MODULE_NAME + '::open_sqllite_db()::The following '
                              'unhandled exception occurred: ' + e.message)
            return None


