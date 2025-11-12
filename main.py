import os
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Product, Order, Message

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

app = FastAPI(title="Radha Kripa Store API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: str | None = None
    role: str | None = None


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str):
    return db["user"].find_one({"email": email})


def get_user(user_id: str):
    try:
        return db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(user_id)
    if user is None:
        raise credentials_exception
    return {"_id": str(user["_id"]), "email": user["email"], "role": role or user.get("role", "customer"), "name": user.get("name", "")}


async def get_current_admin(current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return current


@app.get("/")
def read_root():
    return {"name": "Radha Kripa Store API", "status": "ok"}


@app.get("/test")
def test_database():
    info = {"backend": "running", "database": "disconnected"}
    try:
        db.list_collection_names()
        info["database"] = "connected"
    except Exception as e:
        info["error"] = str(e)
    return info


@app.post("/auth/register")
def register(user: User):
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_dict = user.model_dump()
    user_dict["password_hash"] = get_password_hash(user.password_hash)
    user_dict["created_at"] = datetime.utcnow()
    user_dict["updated_at"] = datetime.utcnow()
    inserted_id = db["user"].insert_one(user_dict).inserted_id
    return {"_id": str(inserted_id)}


@app.post("/auth/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": str(user["_id"]), "role": user.get("role", "customer")})
    return {"access_token": access_token, "token_type": "bearer"}


# Admin-secured product management
@app.post("/admin/products")
async def create_product(product: Product, _: dict = Depends(get_current_admin)):
    data = product.model_dump()
    data["created_at"] = datetime.utcnow()
    data["updated_at"] = datetime.utcnow()
    product_id = db["product"].insert_one(data).inserted_id
    return {"_id": str(product_id)}


@app.get("/products")
async def list_products(category: str | None = None):
    query = {"in_stock": True}
    if category:
        query["category"] = category
    items = list(db["product"].find(query).sort("created_at", -1))
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.get("/products/{product_id}")
async def get_product(product_id: str):
    try:
        it = db["product"].find_one({"_id": ObjectId(product_id)})
        if not it:
            raise HTTPException(status_code=404, detail="Not found")
        it["_id"] = str(it["_id"])
        return it
    except Exception:
        raise HTTPException(status_code=404, detail="Not found")


@app.post("/orders")
async def create_order(order: Order, current=Depends(get_current_user)):
    data = order.model_dump()
    data["user_id"] = current["_id"]
    data["created_at"] = datetime.utcnow()
    data["updated_at"] = datetime.utcnow()
    order_id = db["order"].insert_one(data).inserted_id
    return {"_id": str(order_id)}


@app.get("/me", dependencies=[Depends(get_current_user)])
async def me(current=Depends(get_current_user)):
    return current


@app.post("/support")
async def support_message(msg: Message):
    data = msg.model_dump()
    data["created_at"] = datetime.utcnow()
    message_id = db["message"].insert_one(data).inserted_id
    return {"_id": str(message_id)}


# Simple admin dashboard stats (secured)
@app.get("/admin/stats")
async def admin_stats(_: dict = Depends(get_current_admin)):
    return {
        "users": db["user"].count_documents({}),
        "products": db["product"].count_documents({}),
        "orders": db["order"].count_documents({}),
        "messages": db["message"].count_documents({}),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
