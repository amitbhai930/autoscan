from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
import os

class Database:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance.init_database()
        return cls._instance
    
    def init_database(self):
        # For simplicity, using SQLite. In production, use PostgreSQL or MySQL
        db_path = "autoscanz.db"
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        self.Session = sessionmaker(bind=self.engine)
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        # Initialize default admin user if not exists
        self.create_default_admin()
    
    def get_session(self):
        return self.Session()
    
    def create_default_admin(self):
        from auth import Auth
        from models import User
        
        session = self.get_session()
        try:
            admin = session.query(User).filter_by(username='admin').first()
            if not admin:
                auth = Auth()
                password_hash = auth.hash_password('admin')
                admin = User(
                    username='admin',
                    password_hash=password_hash,
                    email='admin@autoscanz.com',
                    is_admin=True
                )
                session.add(admin)
                session.commit()
                print("Default admin user created: admin/admin")
        except Exception as e:
            print(f"Error creating admin user: {e}")
            session.rollback()
        finally:
            session.close()