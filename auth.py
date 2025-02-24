from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Initialize FastAPI app
app = FastAPI()

# Database Configuration (PostgreSQL)
DATABASE_URL = "postgresql://postgres:1444@localhost:5432/Yuli"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Database Model for User
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    FullName = Column(String, nullable=False)
    Grade = Column(Integer, nullable=False)
    email = Column(String, unique=True, nullable=False)
    Password = Column(String, nullable=False)

# Create tables
Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Model for User Registration
class User(BaseModel):
    FullName: str
    Grade: int
    email: EmailStr
    Password: str
    confirm_password: str

# Pydantic Model for User Login
class LoginUser(BaseModel):
    email: EmailStr
    Password: str

# User Registration Endpoint
@app.post("/register/")
async def register_user(user: User, db: Session = Depends(get_db)):
    if user.Password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match!")

    existing_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists!")

    hashed_password = hash_password(user.Password)
    new_user = UserDB(
        FullName=user.FullName,
        Grade=user.Grade,
        email=user.email,
        Password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully!"}

# User Login Endpoint
@app.post("/login/")
async def login_user(user: LoginUser, db: Session = Depends(get_db)):
    existing_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found!")

    if not verify_password(user.Password, existing_user.Password):
        raise HTTPException(status_code=401, detail="Incorrect password!")

    return {"message": "Login successful!"}

# Run FastAPI Server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
