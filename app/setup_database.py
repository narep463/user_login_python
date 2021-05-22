
import mysql.connector as mysqldb
from sqlalchemy.sql.expression import false
import settings
from sqlalchemy import create_engine


def check_and_create_db():
    mysqldb_connection = create_engine("mysql+mysqldb://%s:%s@%s:3306/%s" % (settings.DB_USER, settings.DB_PASSWORD, settings.DB_HOST, settings.DB_DATABASE), echo=False).connect()

    mycursor = mysqldb_connection

    rs = mycursor.execute("SHOW TABLES")

    table_exists = False
    for table in rs:
        if table[0] == settings.DB_TABLE:
            table_exists = True

    if not table_exists:
        mycursor.execute("CREATE TABLE %s (username VARCHAR(50) UNIQUE, password VARCHAR(255), email varchar(50), phone varchar(30))"%settings.DB_TABLE)


if __name__=='__main__':
    check_and_create_db()

