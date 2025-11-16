import os
from datetime import datetime
from typing import Optional, List, Any

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from bson import ObjectId
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from schemas import User, TrackerEntry, FilterQuery, LoginRequest, SignupRequest, UpdateEntry

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGO = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="Tracking API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def to_str_id(doc: dict) -> dict:
    if doc is None:
        return doc
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        u = db["user"].find_one({"_id": ObjectId(user_id)})
        if not u:
            raise HTTPException(status_code=401, detail="User not found")
        return to_str_id(u)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/")
def root():
    return {"message": "Tracking API running"}


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


# Auth endpoints
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


@app.post("/auth/signup", response_model=TokenResponse)
def signup(body: SignupRequest):
    # Ensure unique email
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
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not pwd_context.verify(body.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({"sub": str(u["_id"]), "email": u["email"], "iat": int(datetime.utcnow().timestamp())}, JWT_SECRET, algorithm=JWT_ALGO)
    return TokenResponse(access_token=token, user=to_str_id(u))


# Entries CRUD
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
        # Simple substring search on title/notes
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


# Export endpoints
import csv
from io import StringIO, BytesIO
from fastapi.responses import StreamingResponse


@app.get("/export/csv")
def export_csv(user=Depends(get_current_user)):
    cursor = db["trackerentry"].find({"user_id": user["id"]})
    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["id", "title", "category", "amount", "status", "date", "notes"]) 
    for d in cursor:
        writer.writerow([str(d.get("_id")), d.get("title"), d.get("category"), d.get("amount"), d.get("status"), d.get("date"), (d.get("notes") or "").replace("\n", " ")])
    sio.seek(0)
    headers = {"Content-Disposition": "attachment; filename=entries.csv"}
    return StreamingResponse(iter([sio.getvalue()]), media_type="text/csv", headers=headers)


# PDF export (simple text-based PDF using reportlab)
@app.get("/export/pdf")
def export_pdf(user=Depends(get_current_user)):
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
    except Exception:
        raise HTTPException(status_code=500, detail="PDF export dependency missing: reportlab")

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    textobj = c.beginText(40, 750)
    textobj.textLine("Entries Export")
    textobj.textLine("")

    cursor = db["trackerentry"].find({"user_id": user["id"]}).limit(500)
    for d in cursor:
        line = f"{str(d.get('_id'))} | {d.get('title')} | {d.get('category')} | {d.get('amount')} | {d.get('status')}"
        textobj.textLine(line)
    c.drawText(textobj)
    c.showPage()
    c.save()
    buffer.seek(0)

    headers = {"Content-Disposition": "attachment; filename=entries.pdf"}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
