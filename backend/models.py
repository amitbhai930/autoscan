from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(100))
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    scans = relationship("Scan", back_populates="user")

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    target_url = Column(String(500), nullable=False)
    scan_type = Column(String(50))
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    result_json = Column(Text)
    vulnerabilities_found = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    cve_matches = Column(Integer, default=0)
    
    user = relationship("User", back_populates="scans")

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    cve_id = Column(String(50))
    severity = Column(String(20))  # critical, high, medium, low
    type = Column(String(50))  # xss, sql, csrf, etc.
    description = Column(Text)
    remediation = Column(Text)
    affected_component = Column(String(200))
    
class CVEDatabase(Base):
    __tablename__ = 'cve_database'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    severity = Column(String(20))
    cvss_score = Column(String(10))
    affected_software = Column(Text)
    published_date = Column(DateTime)
    last_updated = Column(DateTime)