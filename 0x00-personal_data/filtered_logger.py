#!/usr/bin/env python3
"""
This module contains a log filter function
"""
import re
from typing import List
import logging
import os
import mysql.connector


PII_FIELDS = ("name", "email", "password", "ssn", "phone")


def get_logger() -> logging.Logger:
    """
    Returns a logging.Logger object.

    The logger is named "user_data" and only logs up to logging.INFO level.
    It does not propagate messages to other loggers.
    It has a StreamHandler with RedactingFormatter as formatter.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the database
        (mysql.connector.connection.MySQLConnection object).

    The database credentials are obtained from environment variables:
    - PERSONAL_DATA_DB_USERNAME: Username for the database (default: "root")
    - PERSONAL_DATA_DB_PASSWORD: Password for the database (default: "")
    - PERSONAL_DATA_DB_HOST: Hostname for the database (default: "localhost")
    - PERSONAL_DATA_DB_NAME: Name of the database
    """
    username = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    if not db_name:
        raise ValueError(
            "The database name must be set in the PERSONAL_DATA_DB_NAME "
            "environment variable."
        )

    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=db_name
    )


def main():
    """Logs the information about user records in a table."""
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


def filter_datum(
        fields: List[str], redaction: str, message: str,
        separator: str) -> str:
    """
    Function that returns the log message obfuscated

    Arguments:
        fields: a list of strings representing all fields to obfuscate
        redaction: a string representing by what the field
            will be obfuscated
        message: a string representing the log line
        separator: a string representing by which character
            is separating all fields in the log line (message)

    returns:
        str: The log message with specified fields obfuscated.
    """
    pattern = '|'.join([f'(?<={field}=)[^{separator}]+' for field in fields])
    return re.sub(pattern, redaction, message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialization definition"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats the return message base on filter_datum"""
        original_message = super().format(record)
        return filter_datum(self.fields,
                            self.REDACTION, original_message, self.SEPARATOR)


if __name__ == "__main__":
    main()
