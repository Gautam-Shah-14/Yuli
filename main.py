from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from pymongo import MongoClient

# Initialize FastAPI app
app = FastAPI()

# My MongoDB URI
MONGO_URI = "mongodb://localhost:27017/user_data"
client = MongoClient(MONGO_URI)
db = client["user_database"]  # Database name
users_collection = db["users"]  # Collection name

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

# Pydantic Model for User
class User(BaseModel):
    full_name: str
    grade: int
    email: EmailStr
    password: str
    confirm_password: str

# Create User (POST)
@app.post("/register/")
async def register_user(user: User):
    # Check if passwords match
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match!")

    # Check if user already exists
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists!")

    # Hash password before storing
    hashed_password = hash_password(user.password)
    
    # Prepare user data for MongoDB (excluding confirm_password)
    user_dict = {
        "full_name": user.full_name,
        "grade": user.grade,
        "email": user.email,
        "password": hashed_password
    }
    
    # Insert into MongoDB
    users_collection.insert_one(user_dict)
    return {"message": "User registered successfully!"}

# Run FastAPI Server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
