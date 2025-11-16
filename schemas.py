"""
Database Schemas for Tracking App

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase of the class name.

Example:
- User -> "user"
- TrackerEntry -> "trackerentry"
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime


class User(BaseModel):
    """User accounts collection"""
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    avatar_url: Optional[str] = Field(None, description="Optional avatar URL")
    is_active: bool = Field(True, description="Whether user is active")


class TrackerEntry(BaseModel):
    """Entries recorded by users"""
    user_id: str = Field(..., description="Owner user id as string")
    title: str = Field(..., description="Entry title")
    category: str = Field(..., description="Category tag")
    amount: float = Field(..., ge=0, description="Amount or value")
    status: str = Field("open", description="Status of entry")
    notes: Optional[str] = Field(None, description="Optional notes")
    date: datetime = Field(default_factory=datetime.utcnow, description="Timestamp for the entry")


class FilterQuery(BaseModel):
    q: Optional[str] = None
    category: Optional[str] = None
    status: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    sort_by: Optional[str] = None  # date|amount|title
    sort_dir: Optional[str] = None  # asc|desc
    limit: Optional[int] = Field(100, ge=1, le=1000)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class UpdateEntry(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    amount: Optional[float] = Field(None, ge=0)
    status: Optional[str] = None
    notes: Optional[str] = None
    date: Optional[datetime] = None
