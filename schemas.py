"""
Database Schemas for GPS Tracking App

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase of the class name.

Example:
- User -> "user"
- Device -> "device"
- LocationPing -> "locationping"
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
    role: str = Field("user", description="user|admin")


# =========================
# GPS Tracking domain models
# =========================
class CircleGeofence(BaseModel):
    name: str
    lat: float
    lng: float
    radius_m: float = Field(..., gt=0)


class Device(BaseModel):
    owner_user_id: str = Field(..., description="Owner user id as string")
    name: str
    device_id: str = Field(..., description="IMEI or Device ID (unique)")
    api_key: Optional[str] = Field(None, description="Device API key for pushing pings")
    is_active: bool = True
    speed_limit_kmh: Optional[float] = Field(120, ge=0)
    geofences: List[CircleGeofence] = []
    last_seen: Optional[datetime] = None
    last_lat: Optional[float] = None
    last_lng: Optional[float] = None
    last_speed: Optional[float] = None
    last_heading: Optional[float] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    speed_limit_kmh: Optional[float] = Field(None, ge=0)
    geofences: Optional[List[CircleGeofence]] = None


class LocationPing(BaseModel):
    device_id: str
    lat: float
    lng: float
    speed_kmh: Optional[float] = Field(0, ge=0)
    heading_deg: Optional[float] = Field(0, ge=0, le=360)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HistoryQuery(BaseModel):
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    limit: Optional[int] = Field(1000, ge=1, le=10000)


class Alert(BaseModel):
    device_id: str
    type: str  # geofence_enter, geofence_exit, speed, offline
    message: str
    level: str = Field("info", description="info|warning|critical")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    meta: dict = {}


# Legacy tracker entry models kept for compatibility with existing pages
class TrackerEntry(BaseModel):
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
