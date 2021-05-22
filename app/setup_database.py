
import mysql.connector as mysqldb
import settings



def check_and_create_db():
    mysqldb_connection = mysqldb.connect(user=settings.DB_USER, password=settings.DB_PASSWORD, host=settings.DB_HOST, auth_plugin='mysql_native_password')

    mycursor = mysqldb_connection.cursor()

    mycursor.execute("SHOW DATABASES")

    db_exists = False
    for db in mycursor:
        if db[0] == settings.DB_DATABASE:
            db_exists = True

    if not db_exists:
        mycursor.execute("CREATE DATABASE %s"%settings.DB_DATABASE)


    mysqldb_connection = mysqldb.connect(user=settings.DB_USER, password=settings.DB_PASSWORD, database=settings.DB_DATABASE, host=settings.DB_HOST, auth_plugin='mysql_native_password')

    mycursor = mysqldb_connection.cursor()

    mycursor.execute("SHOW TABLES")

    table_exists = False
    for table in mycursor:
        if table[0] == settings.DB_TABLE:
            table_exists = True

    if not table_exists:
        mycursor.execute("CREATE TABLE %s (username VARCHAR(50) UNIQUE, password VARCHAR(255), email varchar(50), phone varchar(30))"%settings.DB_TABLE)


if __name__=='__main__':
    check_and_create_db()

