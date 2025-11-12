"""
Database Schemas for Radha Kripa Store

Collections:
- user: admin and customers
- product: dhoop batti, agarbatti, perfumes, etc.
- order: customer orders
- message: live support chat/messages
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Hashed password")
    role: str = Field("customer", description="role: admin or customer")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Product(BaseModel):
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price")
    category: str = Field(..., description="Category: dhoop, agarbatti, perfume, batti")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    in_stock: bool = Field(True, description="In stock")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class OrderItem(BaseModel):
    product_id: str
    quantity: int = Field(ge=1)
    price: float

class Order(BaseModel):
    user_id: Optional[str] = Field(None, description="Customer user id or None for guest")
    items: List[OrderItem]
    total: float
    status: str = Field("pending", description="pending, paid, shipped, delivered, cancelled")
    shipping_address: str
    phone: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Message(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    user_id: Optional[str] = None
    content: str
    created_at: Optional[datetime] = None
