from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Database URL
DATABASE_URL = 'mysql+pymysql://root:@localhost/edi1'  # Change as necessary

# Create the engine and the base class for declarative models
engine = create_engine(DATABASE_URL)
Base = declarative_base()

DBSession = sessionmaker(bind=engine)
