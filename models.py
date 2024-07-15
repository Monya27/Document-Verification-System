from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from db_setup import Base

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    full_name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    username = Column(String(50), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    security_id = Column(String(5), nullable=False)
    mobile_number = Column(String(15))
    previous_company = Column(String(100))
    current_company = Column(String(100))
    is_verifier = Column(Boolean, default=False)
    
    file_records = relationship("FileRecord", back_populates="user")

class FileRecord(Base):
    __tablename__ = 'file_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    file_path = Column(String(255))
    file_hash = Column(String(64))
    random_number = Column(Integer)
    security_id = Column(String(5))
    
    user = relationship("User", back_populates="file_records")
