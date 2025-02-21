from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from register import UserDB, get_db  # Import UserDB and get_db from register.py

# Initialize FastAPI app
app = FastAPI()

# Database Configuration
DATABASE_URL = "postgresql://postgres:1444@localhost:5432/Yuli"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Pydantic Model for Login
class LoginUser(BaseModel):
    email: EmailStr
    Password: str

# User Login (POST)
@app.post("/login/")
async def login_user(user: LoginUser, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found!")
    
    # Verify password
    if not verify_password(user.Password, existing_user.Password):
        raise HTTPException(status_code=401, detail="Incorrect password!")

    return {"message": "Login successful!"}
