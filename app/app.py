from http.server import HTTPServer, SimpleHTTPRequestHandler
from logging import error
from mysql.connector import errors

from traitlets.traitlets import validate
import settings
import mysql.connector as mysqldb
from random import randint
import json
import hashlib
import binascii
import os
import re
from datetime import datetime, timedelta


mysqldb_connection = mysqldb.connect(user=settings.DB_USER, password='Gopalvenu@113',
                                     database=settings.DB_DATABASE, host='localhost', auth_plugin='mysql_native_password')

sessions = {}

class GetHandler(SimpleHTTPRequestHandler):

    def do_GET(self):
        routes = {
            "/profile": self.profile
        }
        try:
            response = 200
            cookies = self.parse_cookies(self.headers['Cookie'])
            if "sid" in cookies:
                self.user = cookies["sid"] if (cookies["sid"] in sessions) else False
            else:
                self.user = False
            content = routes[self.path]()
        except:
            response = 404
            content = "Not Found"
        self.send_response(response)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(content, "utf-8"))
        return

    def profile(self):
        try:
            if self.user:
                if self.user in sessions:
                    username = sessions[self.user]['username']
                    session_validation = self.validate_session_time(self.user)
                    if not session_validation:
                        cur = mysqldb_connection.cursor(buffered=True)
                        cur.execute('SELECT username, email, phone from login where username="%s"' %username)
                        user_data = cur.fetchone()
                        data = {"user_name": user_data[0], "email": user_data[1], "phone": user_data[2]}
                        return json.dumps(data)
                    return session_validation
            return "Please login to view your profile"
        except Exception as e:
            return str(e)
    
    def validate_session_time(self, sid):
        session_time = sessions[sid]['session_time']
        if datetime.now() - timedelta(minutes=5) > session_time:
            self.cookie = "sid="
            del sessions[self.user]
            return "Session TimedOut, Please log in again to view the profile"
        return None


    def do_POST(self):
        routes = {
            "/login": self.login,
            "/logout": self.logout,
            "/signup": self.signup
        }
        try:
            self.cookie = None
            cookies = self.parse_cookies(self.headers['Cookie'])
            if "sid" in cookies:
                self.user = cookies["sid"] if (cookies["sid"] in sessions) else None
            else:
                self.user = None
            content_length = int(self.headers['Content-Length'])
            try:
                post_data = self.rfile.read(content_length)
                post_data = json.loads(post_data) or {}
            except:
                post_data = {}
            content, response = routes[self.path](post_data)
        except Exception as e:
            content = str(e)
            response = 404
        self.send_response(response)
        self.send_header('Content-type', 'text/html')
        if self.cookie:
            self.send_header('Set-Cookie', self.cookie)
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
        email = post_data.get('email', None)
        phone = post_data.get('phone', None)

        validation_errors = self.validate_signup_data(username, password, email, phone)

        if not validation_errors:
            password = self.hash_password(password)
            cur = mysqldb_connection.cursor()
            cur.execute('INSERT INTO login (username, password, email, phone) VALUES ("%s", "%s", "%s", "%s")' % (
                username, password, email, phone))
            mysqldb_connection.commit()
            cur.close()
            return "User Created Successfully", 200
        else:
            return str(validation_errors), 400
    
    def validate_signup(username, password, email, phone):
        errors = []
        if '@' not in email:
            errors.append('Not a valid email')
        if len(username) > 8:
            errors.append('Length of username must not exceed 8 characters')
        if not re.match("^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{1,6}$", password):
            errors.append('Password should contain one letter, one number, any of these [_, -, #] symbols, and must not exceed 6 characters')
        if not re.match("^(?:(?:\+|0{0,2})91(\s*[\-]\s*)?|[0]?)?[6789]\d{9}$", phone):
            errors.append('Not a valid phone number')
        return ", ".join(errors)
    
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
            sid = self.generate_sid()
            self.cookie = "sid={}".format(sid)
            sessions[sid] = {"username": username, "session_time":datetime.now()}
            return "User logged in successfully", 200
        else:
            return "Invalid Password", 400
    
    def generate_sid(self):
        return "".join(str(randint(1,9)) for _ in range(100))
    
    def logout(self, post_data):
        if not self.user:
            return "Can't Log Out: No User Logged In", 400
        self.cookie = "sid="
        del sessions[self.user]
        return "Logout Successfully", 200

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
    
    def parse_cookies(self, cookie_list):
        return dict(((c.split("=")) for c in cookie_list.split(";"))) \
        if cookie_list else {}

Handler=GetHandler

httpd=HTTPServer(("localhost", 8080), Handler)
httpd.serve_forever()
