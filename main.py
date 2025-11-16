import os
from datetime import datetime, timedelta
from typing import Optional, List, Any, Dict

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from bson import ObjectId
from passlib.context import CryptContext
import jwt
import csv
from io import StringIO, BytesIO

from database import db
from schemas import (
    User,
    TrackerEntry,
    FilterQuery,
    LoginRequest,
    SignupRequest,
    UpdateEntry,
    Device,
    DeviceUpdate,
    LocationPing,
    HistoryQuery,
    Alert,
)

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGO = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="GPS Tracking API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------
# Helpers
# ------------------------------------

def to_str_id(doc: dict) -> dict:
    if doc is None:
        return doc
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def auth_user_from_token(token: str) -> dict:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    u = db["user"].find_one({"_id": ObjectId(user_id)})
    if not u:
        raise HTTPException(status_code=401, detail="User not found")
    return to_str_id(u)


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        return auth_user_from_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ------------------------------------
# Root + health
# ------------------------------------
@app.get("/")
def root():
    return {"message": "GPS Tracking API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            try:
                cols = db.list_collection_names()
                response["collections"] = cols[:10]
                response["connection_status"] = "Connected"
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but error: {str(e)[:60]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:60]}"
    return response


# ------------------------------------
# Auth endpoints
# ------------------------------------
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


@app.post("/auth/signup", response_model=TokenResponse)
def signup(body: SignupRequest):
    if db["user"].find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = pwd_context.hash(body.password)
    user = User(name=body.name, email=body.email, password_hash=hashed)
    user_id = db["user"].insert_one(user.model_dump()).inserted_id
    token = jwt.encode({"sub": str(user_id), "email": body.email, "iat": int(datetime.utcnow().timestamp())}, JWT_SECRET, algorithm=JWT_ALGO)
    u = db["user"].find_one({"_id": user_id})
    return TokenResponse(access_token=token, user=to_str_id(u))


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest):
    u = db["user"].find_one({"email": body.email})
    if not u or not pwd_context.verify(body.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({"sub": str(u["_id"]), "email": u["email"], "iat": int(datetime.utcnow().timestamp())}, JWT_SECRET, algorithm=JWT_ALGO)
    return TokenResponse(access_token=token, user=to_str_id(u))


# ------------------------------------
# Devices CRUD
# ------------------------------------
@app.post("/devices", response_model=dict)
def create_device(body: Device, user=Depends(get_current_user)):
    if body.owner_user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Cannot create for another user")
    if db["device"].find_one({"device_id": body.device_id}):
        raise HTTPException(status_code=400, detail="Device ID already exists")
    inserted = db["device"].insert_one(body.model_dump())
    doc = db["device"].find_one({"_id": inserted.inserted_id})
    return to_str_id(doc)


@app.get("/devices", response_model=List[dict])
def list_devices(user=Depends(get_current_user)):
    cur = db["device"].find({"owner_user_id": user["id"]}).sort("created_at", -1)
    return [to_str_id(d) for d in cur]


@app.put("/devices/{device_db_id}", response_model=dict)
def update_device(device_db_id: str, patch: DeviceUpdate, user=Depends(get_current_user)):
    res = db["device"].update_one({"_id": oid(device_db_id), "owner_user_id": user["id"]}, {"$set": patch.model_dump(exclude_none=True)})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    doc = db["device"].find_one({"_id": oid(device_db_id)})
    return to_str_id(doc)


@app.delete("/devices/{device_db_id}", response_model=dict)
def delete_device(device_db_id: str, user=Depends(get_current_user)):
    doc = db["device"].find_one_and_delete({"_id": oid(device_db_id), "owner_user_id": user["id"]})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return {"deleted": True, "id": device_db_id}


# Admin endpoints (simple)
@app.get("/admin/users", response_model=List[dict])
def admin_list_users(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    cur = db["user"].find().limit(200)
    return [to_str_id(u) for u in cur]


@app.get("/admin/devices", response_model=List[dict])
def admin_list_devices(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    cur = db["device"].find().limit(500)
    return [to_str_id(d) for d in cur]


# ------------------------------------
# Location ingest + history
# ------------------------------------
class IngestRequest(BaseModel):
    device_id: str
    lat: float
    lng: float
    speed_kmh: Optional[float] = 0
    heading_deg: Optional[float] = 0
    timestamp: Optional[datetime] = None
    api_key: Optional[str] = None


@app.post("/ingest", response_model=dict)
def ingest_location(body: IngestRequest):
    # Device authentication simplified: by device_id (and optional api_key in future)
    dev = db["device"].find_one({"device_id": body.device_id, "is_active": True})
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found or inactive")

    ping = LocationPing(
        device_id=body.device_id,
        lat=body.lat,
        lng=body.lng,
        speed_kmh=body.speed_kmh or 0,
        heading_deg=body.heading_deg or 0,
        timestamp=body.timestamp or datetime.utcnow(),
    )
    db["locationping"].insert_one(ping.model_dump())

    # Update device last known state
    updates = {
        "last_seen": ping.timestamp,
        "last_lat": ping.lat,
        "last_lng": ping.lng,
        "last_speed": ping.speed_kmh,
        "last_heading": ping.heading_deg,
    }
    db["device"].update_one({"_id": dev["_id"]}, {"$set": updates})

    # Alerts: speed + simple geofence enter
    alerts: List[Dict] = []
    try:
        limit = dev.get("speed_limit_kmh")
        if limit and ping.speed_kmh and ping.speed_kmh > float(limit):
            al = Alert(device_id=body.device_id, type="speed", level="warning", message=f"Speed {ping.speed_kmh}km/h > limit {limit}")
            db["alert"].insert_one(al.model_dump())
            alerts.append(al.model_dump())
        # Geofence enter check
        for gf in dev.get("geofences", []) or []:
            if _within_geofence(ping.lat, ping.lng, gf.get("lat"), gf.get("lng"), gf.get("radius_m")):
                al = Alert(device_id=body.device_id, type="geofence_enter", level="info", message=f"Entered {gf.get('name')}")
                db["alert"].insert_one(al.model_dump())
                alerts.append(al.model_dump())
    except Exception:
        pass

    # Broadcast via WebSocket
    await_broadcast({
        "type": "ping",
        "device": to_str_id(dev),
        "ping": ping.model_dump(),
        "alerts": alerts,
    })

    return {"ingested": True}


@app.get("/devices/{device_id}/history", response_model=List[dict])
def device_history(device_id: str, start: Optional[str] = None, end: Optional[str] = None, limit: int = 1000, user=Depends(get_current_user)):
    dev = db["device"].find_one({"device_id": device_id, "owner_user_id": user["id"]})
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    filt: Dict[str, Any] = {"device_id": device_id}
    if start or end:
        t: Dict[str, Any] = {}
        if start:
            t["$gte"] = datetime.fromisoformat(start)
        if end:
            t["$lte"] = datetime.fromisoformat(end)
        filt["timestamp"] = t
    cur = db["locationping"].find(filt).sort("timestamp", 1).limit(min(max(int(limit), 1), 10000))
    return [to_str_id(d) for d in cur]


@app.get("/alerts", response_model=List[dict])
def list_alerts(user=Depends(get_current_user)):
    # show alerts for user's devices
    device_ids = [d.get("device_id") for d in db["device"].find({"owner_user_id": user["id"]})]
    cur = db["alert"].find({"device_id": {"$in": device_ids}}).sort("created_at", -1).limit(200)
    return [to_str_id(d) for d in cur]


# ------------------------------------
# Export history CSV/PDF
# ------------------------------------
@app.get("/export/history/csv")
def export_history_csv(device_id: str, start: Optional[str] = None, end: Optional[str] = None, user=Depends(get_current_user)):
    dev = db["device"].find_one({"device_id": device_id, "owner_user_id": user["id"]})
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    filt: Dict[str, Any] = {"device_id": device_id}
    if start or end:
        t: Dict[str, Any] = {}
        if start:
            t["$gte"] = datetime.fromisoformat(start)
        if end:
            t["$lte"] = datetime.fromisoformat(end)
        filt["timestamp"] = t
    cur = db["locationping"].find(filt).sort("timestamp", 1)

    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["timestamp", "lat", "lng", "speed_kmh", "heading_deg"]) 
    for d in cur:
        writer.writerow([
            d.get("timestamp"), d.get("lat"), d.get("lng"), d.get("speed_kmh", 0), d.get("heading_deg", 0)
        ])
    sio.seek(0)
    headers = {"Content-Disposition": f"attachment; filename={device_id}_history.csv"}
    return StreamingResponse(iter([sio.getvalue()]), media_type="text/csv", headers=headers)


@app.get("/export/history/pdf")
def export_history_pdf(device_id: str, start: Optional[str] = None, end: Optional[str] = None, user=Depends(get_current_user)):
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
    except Exception:
        raise HTTPException(status_code=500, detail="PDF export dependency missing: reportlab")

    dev = db["device"].find_one({"device_id": device_id, "owner_user_id": user["id"]})
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    filt: Dict[str, Any] = {"device_id": device_id}
    if start or end:
        t: Dict[str, Any] = {}
        if start:
            t["$gte"] = datetime.fromisoformat(start)
        if end:
            t["$lte"] = datetime.fromisoformat(end)
        filt["timestamp"] = t
    cur = db["locationping"].find(filt).sort("timestamp", 1).limit(2000)

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    textobj = c.beginText(40, 750)
    textobj.textLine(f"History for {device_id}")
    textobj.textLine("")
    for d in cur:
        line = f"{d.get('timestamp')} | {d.get('lat')},{d.get('lng')} | v={d.get('speed_kmh',0)}km/h | hdg={d.get('heading_deg',0)}"
        textobj.textLine(line)
    c.drawText(textobj)
    c.showPage()
    c.save()
    buffer.seek(0)

    headers = {"Content-Disposition": f"attachment; filename={device_id}_history.pdf"}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)


# ------------------------------------
# Legacy Entries (for existing UI compatibility)
# ------------------------------------
@app.post("/entries", response_model=dict)
def create_entry(entry: TrackerEntry, user=Depends(get_current_user)):
    if entry.user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Cannot create for another user")
    eid = db["trackerentry"].insert_one(entry.model_dump()).inserted_id
    doc = db["trackerentry"].find_one({"_id": eid})
    return to_str_id(doc)


@app.get("/entries", response_model=List[dict])
def list_entries(q: Optional[str] = None, category: Optional[str] = None, status: Optional[str] = None,
                 start_date: Optional[str] = None, end_date: Optional[str] = None,
                 sort_by: Optional[str] = None, sort_dir: Optional[str] = None,
                 limit: int = 100, user=Depends(get_current_user)):
    filt: dict[str, Any] = {"user_id": user["id"]}
    if q:
        filt["$or"] = [{"title": {"$regex": q, "$options": "i"}}, {"notes": {"$regex": q, "$options": "i"}}]
    if category:
        filt["category"] = category
    if status:
        filt["status"] = status
    if start_date or end_date:
        dr = {}
        if start_date:
            dr["$gte"] = datetime.fromisoformat(start_date)
        if end_date:
            dr["$lte"] = datetime.fromisoformat(end_date)
        filt["date"] = dr
    sort = None
    if sort_by:
        direction = -1 if (sort_dir or "desc").lower() == "desc" else 1
        sort = [(sort_by, direction)]
    cursor = db["trackerentry"].find(filt)
    if sort:
        cursor = cursor.sort(sort)
    cursor = cursor.limit(min(max(int(limit), 1), 1000))
    return [to_str_id(d) for d in cursor]


@app.get("/entries/{entry_id}", response_model=dict)
def get_entry(entry_id: str, user=Depends(get_current_user)):
    doc = db["trackerentry"].find_one({"_id": ObjectId(entry_id), "user_id": user["id"]})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return to_str_id(doc)


@app.put("/entries/{entry_id}", response_model=dict)
def update_entry(entry_id: str, patch: UpdateEntry, user=Depends(get_current_user)):
    update = {k: v for k, v in patch.model_dump(exclude_unset=True).items()}
    update["updated_at"] = datetime.utcnow()
    res = db["trackerentry"].update_one({"_id": ObjectId(entry_id), "user_id": user["id"]}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    doc = db["trackerentry"].find_one({"_id": ObjectId(entry_id)})
    return to_str_id(doc)


@app.delete("/entries/{entry_id}", response_model=dict)
def delete_entry(entry_id: str, user=Depends(get_current_user)):
    doc = db["trackerentry"].find_one_and_delete({"_id": ObjectId(entry_id), "user_id": user["id"]})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return {"deleted": True, "id": entry_id}


@app.get("/entries/summary", response_model=dict)
def summary(user=Depends(get_current_user)):
    pipeline = [
        {"$match": {"user_id": user["id"]}},
        {"$group": {"_id": "$category", "total": {"$sum": "$amount"}, "count": {"$sum": 1}}},
        {"$sort": {"total": -1}},
    ]
    agg = list(db["trackerentry"].aggregate(pipeline))
    total = sum(a.get("total", 0) for a in agg)
    return {"byCategory": [{"category": a.get("_id"), "total": a.get("total"), "count": a.get("count")} for a in agg], "total": total}


# ------------------------------------
# WebSocket broadcasting
# ------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, List[WebSocket]] = {}  # key: user_id or "*"

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active.setdefault(user_id, []).append(websocket)

    def disconnect(self, user_id: str, websocket: WebSocket):
        arr = self.active.get(user_id, [])
        if websocket in arr:
            arr.remove(websocket)
        if not arr and user_id in self.active:
            del self.active[user_id]

    async def broadcast(self, user_id: str, message: dict):
        # send to user and wildcard
        for uid in [user_id, "*"]:
            for ws in list(self.active.get(uid, [])):
                try:
                    await ws.send_json(message)
                except Exception:
                    try:
                        ws.close()
                    except Exception:
                        pass
                    self.disconnect(uid, ws)


manager = ConnectionManager()


@app.websocket("/ws/track")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    # authenticate from token query param
    if not token:
        await websocket.close(code=4401)
        return
    try:
        user = auth_user_from_token(token)
    except Exception:
        await websocket.close(code=4401)
        return

    await manager.connect(user["id"], websocket)
    try:
        while True:
            # We keep the connection alive; client may send pings but not required
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user["id"], websocket)


async def await_broadcast(message: dict):
    # Determine the target user from device owner if available
    try:
        dev = message.get("device")
        if dev and dev.get("owner_user_id"):
            await manager.broadcast(dev["owner_user_id"], message)
        else:
            await manager.broadcast("*", message)
    except Exception:
        pass


# ------------------------------------
# Utility: geofence distance check (haversine)
# ------------------------------------
from math import radians, sin, cos, asin, sqrt


def _haversine_m(lat1, lon1, lat2, lon2):
    R = 6371000.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    return R * c


def _within_geofence(lat, lng, gf_lat, gf_lng, radius_m):
    if gf_lat is None or gf_lng is None or radius_m is None:
        return False
    return _haversine_m(lat, lng, gf_lat, gf_lng) <= float(radius_m)


# ------------------------------------
# Ingestion + history exports for legacy entries (CSV/PDF) retained in new endpoints above
# ------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
