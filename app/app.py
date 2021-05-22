from http.server import HTTPServer, SimpleHTTPRequestHandler
import settings
import mysql.connector as mysqldb
from random import randint
import json
import hashlib
import binascii
import os


mysqldb_connection = mysqldb.connect(user=settings.DB_USER, password='Gopalvenu@113',
                                     database=settings.DB_DATABASE, host='localhost', auth_plugin='mysql_native_password')


class GetHandler(SimpleHTTPRequestHandler):

    def do_GET(self):
        routes = {
            "/profile": self.profile
        }
        self.cookie = None
        SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        routes = {
            "/login": self.login,
            "/logout": self.logout,
            "/signup": self.signup
        }
        # <--- Gets the size of data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_data = json.loads(post_data)
        content, response = routes[self.path](post_data)
        self.send_response(response)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(bytes(content, "utf-8"))
        return

    def signup(self, post_data):
        required_fields = ['username', 'password', 'email', 'phone']
        missing_fields = []
        for field in required_fields:
            if not post_data.get(field, None):
                missing_fields.append(field)
        if missing_fields:
            return 'Missing fields - %s ' % (', '.join(missing_fields)), 400
        username = post_data.get('username', None)
        password = post_data.get('password', None)
        password = self.hash_password(password)
        email = post_data.get('email', None)
        phone = post_data.get('phone', None)

        # add conditions
        cur = mysqldb_connection.cursor()
        cur.execute('INSERT INTO login (username, password, email, phone) VALUES ("%s", "%s", "%s", "%s")' % (
            username, password, email, phone))
        mysqldb_connection.commit()
        cur.close()
        return "User Created Successfully", 200
    
    def login(self, post_data):
        required_fields = ['username', 'password']
        missing_fields = []
        for field in required_fields:
            if not post_data.get(field, None):
                missing_fields.append(field)
        if missing_fields:
            return 'Missing fields - %s ' % (', '.join(missing_fields)), 400
        username = post_data.get('username', None)
        password = post_data.get('password', None)
        #add conditions
        cur = mysqldb_connection.cursor(buffered=True)
        cur.execute('SELECT password from login where username="%s"' %username)
        stored_password = cur.fetchone()[0]
        passwords_matched = self.verify_password(stored_password, password)
        if passwords_matched:
            return "User logged in successfully", 200
        else:
            return "Invalid Password", 400
    
    def logout(self):
        #clear session
        return "Logout Successfully"

    def hash_password(self, password):
        """Hash a password for storing."""
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                    salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')
    
    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha256', 
                                    provided_password.encode('utf-8'), 
                                    salt.encode('ascii'), 
                                    100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

Handler=GetHandler

httpd=HTTPServer(("localhost", 8080), Handler)
httpd.serve_forever()