import unittest
from ipdb.__main__ import set_trace
import requests
from random import randint
import json
from sqlalchemy import create_engine
import settings
import hashlib
import binascii
import os
import time

mysqldb_connection = create_engine("mysql+mysqldb://%s:%s@%s:3306/%s" % (settings.DB_USER, settings.DB_PASSWORD, settings.DB_HOST, settings.DB_DATABASE), echo=False).connect()



class TestUserRequestHandler(unittest.TestCase):
    
    def test_do_GET_profile_without_login(self):
        response = requests.get('http://localhost:8080/profile')
        self.assertEqual(response._content.decode("utf-8"), 'Please login to view your profile')
        self.assertEqual(response.status_code, 200)
    
    def test_do_POST_signup_new_user(self):
        data = {'username': 'test%s'%randint(0, 99), 'password': 'test#1', 'email':'test@email.com', 'phone':'9876543210'}
        response = requests.post('http://localhost:8080/signup', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'User Created Successfully')
        self.assertEqual(response.status_code, 200)
    
    def test_do_POST_signup_new_user_username_validation(self):
        data = {'username': 'testsdas%s'%randint(0, 99), 'password': 'test#1', 'email':'test@email.com', 'phone':'9876543210'}
        response = requests.post('http://localhost:8080/signup', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'Length of username must not exceed 8 characters')
        self.assertEqual(response.status_code, 400)
    
    def test_do_POST_signup_new_user_password_validation(self):
        data = {'username': 'test%s'%randint(0, 99), 'password': 'test@1', 'email':'test@email.com', 'phone':'9876543210'}
        response = requests.post('http://localhost:8080/signup', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'Password should contain one letter, one number, any of these [_, -, #] symbols, and must not exceed 6 characters')
        self.assertEqual(response.status_code, 400)
    
    def test_do_POST_signup_new_user_password_validation_max_length(self):
        data = {'username': 'test%s'%randint(0, 99), 'password': 'test#221', 'email':'test@email.com', 'phone':'9876543210'}
        response = requests.post('http://localhost:8080/signup', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'Password should contain one letter, one number, any of these [_, -, #] symbols, and must not exceed 6 characters')
        self.assertEqual(response.status_code, 400)
    
    def test_do_POST_signup_new_user_phone_validation(self):
        data = {'username': 'test%s'%randint(0, 99), 'password': 'test#2', 'email':'test@email.com', 'phone':'9876s543210'}
        response = requests.post('http://localhost:8080/signup', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'Not a valid phone number')
        self.assertEqual(response.status_code, 400)
    
    def test_do_POST_signup_new_user_phone_validation_length(self):
        data = {'username': 'test%s'%randint(0, 99), 'password': 'test#2', 'email':'test@email.com', 'phone':'987654321023'}
        response = requests.post('http://localhost:8080/signup', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'Not a valid phone number')
        self.assertEqual(response.status_code, 400)
    
    def test_do_POST_signup_new_user_email_validation(self):
        data = {'username': 'test%s'%randint(0, 99), 'password': 'test#2', 'email':'testemail.com', 'phone':'9876321023'}
        response = requests.post('http://localhost:8080/signup', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'Not a valid email')
        self.assertEqual(response.status_code, 400)
    
    def test_login(self):
        ##create user
        cur = mysqldb_connection
        username = 'tes%s' % randint(0, 100)
        password = 'tes#1'
        email = 'test1@gmail.com'
        phone = '9878767656'
        password_hash = hash_password(password)
        cur.execute('INSERT INTO %s (username, password, email, phone) VALUES ("%s", "%s", "%s", "%s")' % (
                settings.DB_TABLE, username, password_hash, email, phone))
        
        ## test login
        data = {'username': username, 'password': password}
        response = requests.post('http://localhost:8080/login', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'User logged in successfully')
        self.assertEqual(response.status_code, 200)
    
    def test_login_non_existing_user(self):
        data = {'username': 'tsteu', 'password': '56#er'}
        response = requests.post('http://localhost:8080/login', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'User does not exist')
        self.assertEqual(response.status_code, 400)
    
    def test_logout(self):
        ##create user
        cur = mysqldb_connection
        username = 'tes%s' % randint(0, 100)
        password = 'tes#1'
        email = 'test1@gmail.com'
        phone = '9878767656'
        password_hash = hash_password(password)
        cur.execute('INSERT INTO %s (username, password, email, phone) VALUES ("%s", "%s", "%s", "%s")' % (
                settings.DB_TABLE, username, password_hash, email, phone))

        ## test login
        data = {'username': username, 'password': password}
        response = requests.post('http://localhost:8080/login', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'User logged in successfully')
        self.assertEqual(response.status_code, 200)

        cookies = response.cookies
        response = requests.post('http://localhost:8080/logout', data=json.dumps(data), cookies=cookies)
        self.assertEqual(response._content.decode("utf-8"), 'Logout Successfully')
        self.assertEqual(response.status_code, 200)
    
    def test_logout_non_logged_in_user(self):
        ##create user
        cur = mysqldb_connection
        username = 'tes%s' % randint(0, 100)
        password = 'tes#1'
        email = 'test1@gmail.com'
        phone = '9878767656'
        password_hash = hash_password(password)
        cur.execute('INSERT INTO %s (username, password, email, phone) VALUES ("%s", "%s", "%s", "%s")' % (
                settings.DB_TABLE, username, password_hash, email, phone))
        
        data = {'username': username, 'password': password}
        response = requests.post('http://localhost:8080/logout', data=json.dumps(data), cookies={})
        self.assertEqual(response._content.decode("utf-8"), "Can't Log Out: No User Logged In")
        self.assertEqual(response.status_code, 400)
    
    def test_do_GET_profile_with_login(self):
        ##create user
        cur = mysqldb_connection
        username = 'tes%s' % randint(0, 100)
        password = 'tes#1'
        email = 'test1@gmail.com'
        phone = '9878767656'
        password_hash = hash_password(password)
        cur.execute('INSERT INTO %s (username, password, email, phone) VALUES ("%s", "%s", "%s", "%s")' % (
                settings.DB_TABLE, username, password_hash, email, phone))

        ## test login
        data = {'username': username, 'password': password}
        response = requests.post('http://localhost:8080/login', data=json.dumps(data))
        self.assertEqual(response._content.decode("utf-8"), 'User logged in successfully')
        self.assertEqual(response.status_code, 200)

        cookies = response.cookies
        response = requests.get('http://localhost:8080/profile', cookies=cookies)
        self.assertEqual(response.status_code, 200)

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

if __name__ == '__main__':
    unittest.main()
