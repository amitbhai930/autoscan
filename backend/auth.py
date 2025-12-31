import hashlib
import jwt
import datetime
from functools import wraps
from flask import request, jsonify
import os
from models import User
from database import Database

class Auth:
    def __init__(self):
        self.secret_key = os.environ.get('SECRET_KEY', 'autoscanz-secret-key-2024')
        self.algorithm = 'HS256'
        self.db = Database()
    
    def hash_password(self, password):
        """Hash a password using SHA-256 with salt"""
        salt = "autoscanz-salt-2024"
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def verify_password(self, password, password_hash):
        """Verify a password against its hash"""
        return self.hash_password(password) == password_hash
    
    def generate_token(self, user_id, username, is_admin=False):
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'username': username,
            'is_admin': is_admin,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def login_user(self, username, password):
        """Authenticate user and return token"""
        session = self.db.get_session()
        try:
            user = session.query(User).filter_by(username=username).first()
            if user and self.verify_password(password, user.password_hash):
                # Update last login
                user.last_login = datetime.datetime.utcnow()
                session.commit()
                
                token = self.generate_token(user.id, user.username, user.is_admin)
                return {
                    'token': token,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'is_admin': user.is_admin
                    }
                }
        except Exception as e:
            print(f"Login error: {e}")
        finally:
            session.close()
        return None
    
    def register_user(self, username, password, email):
        """Register new user"""
        session = self.db.get_session()
        try:
            # Check if user exists
            existing = session.query(User).filter_by(username=username).first()
            if existing:
                return {'error': 'Username already exists'}
            
            # Create new user
            password_hash = self.hash_password(password)
            user = User(
                username=username,
                password_hash=password_hash,
                email=email,
                is_admin=False
            )
            session.add(user)
            session.commit()
            
            token = self.generate_token(user.id, user.username, user.is_admin)
            return {
                'token': token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin
                }
            }
        except Exception as e:
            session.rollback()
            print(f"Registration error: {e}")
            return {'error': 'Registration failed'}
        finally:
            session.close()