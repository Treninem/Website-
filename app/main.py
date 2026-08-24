import hashlib,json,secrets,string,sqlite3
from contextlib import asynccontextmanager
from datetime import datetime,timedelta,timezone
from fastapi import Depends,FastAPI,Header,HTTPException
from pydantic import BaseModel,Field
from passlib.context import CryptContext
from .db import init_db,get_db
pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")
ALPHABET=string.ascii_uppercase+string.digits; SESSION_DAYS=30; ROLES={"owner","admin","manager","worker"}; FIELD_TYPES={"text","number","date","select","textarea","checkbox"}

@asynccontextmanager
async def lifespan(app): init_db(); yield
app=FastAPI(title="Website",version="0.7.0",lifespan=lifespan)
class InviteRequest(BaseModel): role:str="worker"
class RegisterRequest(BaseModel): invite_code:str; username:str=Field(min_length=3,max_length=50,pattern=r"^[A-Za-z0-9_.-]+$"); password:str=Field(min_length=8,max_length=128)
class LoginRequest(BaseModel): username:str; password:str
class ChangeUsernameRequest(BaseModel): new_username:str=Field(min_length=3,max_length=50,pattern=r"^[A-Za-z0-9_.-]+$"); current_password:str
class ChangePasswordRequest(BaseModel): current_password:str; new_password:str=Field(min_length=8,max_length=128)
class ChangeRoleRequest(BaseModel): role:str
class ActiveRequest(BaseModel): active:bool
class FormFieldRequest(BaseModel): label:str=Field(min_length=1,max_length=100); field_type:str="text"; required:bool=False; options:list[str]=[]; position:int=0
class FormCreateRequest(BaseModel): name:str=Field(min_length=1,max_length=120); description:str=""; fields:list[FormFieldRequest]=[]
class FormEntryRequest(BaseModel): data:dict
class EntryStatusRequest(BaseModel): status:str


def code():
 raw=''.join(secrets.choice(ALPHABET) for _ in range(16)); return '-'.join(raw[i:i+4] for i in range(0,16,4))
def token_hash(x): return hashlib.sha256(x.encode()).hexdigest()
def session(db,uid):
 t=secrets.token_urlsafe(48); e=(datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)).isoformat(); db.execute("INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)",(token_hash(t),uid,e)); return t
def audit(db,a,action,typ=None,target=None): db.execute("INSERT INTO audit_log (actor_user_id,action,target_type,target_id) VALUES (?,?,?,?)",(a,action,typ,str(target) if target is not None else None))
def notify(db,uid,title,body=""): db.execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)",(uid,title,body))
def current(authorization:str|None=Header(default=None)):
 if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required")
 with get_db() as db: r=db.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.is_active=1",(token_hash(authorization[7:].strip()),datetime.now(timezone.utc).isoformat())).fetchone()
 if not r: raise HTTPException(401,"Session invalid or expired")
 return dict(r)
def owner(u=Depends(current)):
 if u["role"]!="owner": raise HTTPException(403,"Owner access required")
 return u
def admin(u=Depends(current)):
 if u["role"] not in {"owner","admin"}: raise HTTPException(403,"Administrative access required")
 return u
def management(u=Depends(current)):
 if u["role"] not in {"owner","admin","manager"}: raise HTTPException(403,"Manager access required")
 return u

@app.get("/health")
def health(): return {"status":"ok","version":app.version}
@app.post("/api/invites",status_code=201)
def invite(x:InviteRequest,u=Depends(owner)):
 if x.role not in ROLES or x.role=="owner": raise HTTPException(400,"Invalid role")
 with get_db() as db:
  for _ in range(20):
   try:
    c=code(); cur=db.execute("INSERT INTO invite_keys (code,role) VALUES (?,?)",(c,x.role)); audit(db,u["id"],"invite.created","invite",cur.lastrowid); return {"id":cur.lastrowid,"code":c,"role":x.role,"uses":1}
   except sqlite3.IntegrityError: pass
 raise HTTPException(500,"Could not generate unique invitation")
@app.get("/api/invites")
def invites(u=Depends(owner)):
 with get_db() as db:r=db.execute("SELECT id,code,role,created_at,used_at,CASE WHEN used_by IS NULL THEN 0 ELSE 1 END is_used FROM invite_keys ORDER BY id DESC").fetchall()
 return [dict(x) for x in r]
@app.post("/api/register",status_code=201)
def register(x:RegisterRequest):
 with get_db() as db:
  db.execute("BEGIN IMMEDIATE"); i=db.execute("SELECT * FROM invite_keys WHERE code=?",(x.invite_code.strip().upper(),)).fetchone()
  if not i or i["used_by"] is not None: raise HTTPException(400,"Invalid or used invitation")
  try: cur=db.execute("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",(x.username,pwd_context.hash(x.password),i["role"]))
  except sqlite3.IntegrityError: raise HTTPException(409,"Username is already taken")
  if db.execute("UPDATE invite_keys SET used_by=?,used_at=CURRENT_TIMESTAMP WHERE id=? AND used_by IS NULL",(cur.lastrowid,i["id"])).rowcount!=1: raise HTTPException(409,"Invitation already used")
  audit(db,cur.lastrowid,"account.registered","user",cur.lastrowid); return {"id":cur.lastrowid,"username":x.username,"role":i["role"],"access_token":session(db,cur.lastrowid),"token_type":"bearer"}
@app.post("/api/login")
def login(x:LoginRequest):
 with get_db() as db:
  u=db.execute("SELECT * FROM users WHERE username=?",(x.username,)).fetchone()
  if not u or not u["is_active"] or not pwd_context.verify(x.password,u["password_hash"]): raise HTTPException(401,"Invalid username or password")
  audit(db,u["id"],"account.login","user",u["id"]); return {"access_token":session(db,u["id"]),"token_type":"bearer","user":{"id":u["id"],"username":u["username"],"role":u["role"]}}
@app.get("/api/me")
def me(u=Depends(current)): return {"id":u["id"],"username":u["username"],"role":u["role"]}
@app.put("/api/me/username")
def username(x:ChangeUsernameRequest,u=Depends(current)):
 if not pwd_context.verify(x.current_password,u["password_hash"]): raise HTTPException(400,"Current password is incorrect")
 with get_db() as db:
  try: db.execute("UPDATE users SET username=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(x.new_username,u["id"]))
  except sqlite3.IntegrityError: raise HTTPException(409,"Username is already taken")
  audit(db,u["id"],"account.username_changed","user",u["id"])
 return {"username":x.new_username}
@app.put("/api/me/password")
def password(x:ChangePasswordRequest,u=Depends(current)):
 if not pwd_context.verify(x.current_password,u["password_hash"]): raise HTTPException(400,"Current password is incorrect")
 with get_db() as db: db.execute("UPDATE users SET password_hash=? WHERE id=?",(pwd_context.hash(x.new_password),u["id"])); db.execute("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=?",(u["id"],)); audit(db,u["id"],"account.password_changed","user",u["id"])
 return {"message":"Password changed. Sign in again."}
@app.get("/api/admin/users")
def users(u=Depends(admin)):
 with get_db() as db:r=db.execute("SELECT id,username,role,is_active,created_at FROM users ORDER BY id DESC").fetchall()
 return [dict(x) for x in r]
@app.put("/api/admin/users/{uid}/role")
def role(uid:int,x:ChangeRoleRequest,u=Depends(owner)):
 if x.role not in ROLES or x.role=="owner": raise HTTPException(400,"Invalid role")
 with get_db() as db:
  if not db.execute("SELECT id FROM users WHERE id=?",(uid,)).fetchone(): raise HTTPException(404,"User not found")
  db.execute("UPDATE users SET role=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(x.role,uid)); audit(db,u["id"],"user.role_changed","user",uid)
 return {"id":uid,"role":x.role}
@app.put("/api/admin/users/{uid}/active")
def set_active(uid:int,x:ActiveRequest,u=Depends(admin)):
 if uid==u["id"]: raise HTTPException(400,"You cannot disable your own account")
 with get_db() as db:
  if not db.execute("SELECT id FROM users WHERE id=?",(uid,)).fetchone(): raise HTTPException(404,"User not found")
  db.execute("UPDATE users SET is_active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(int(x.active),uid))
  if not x.active: db.execute("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=?",(uid,))
  audit(db,u["id"],"user.activated" if x.active else "user.deactivated","user",uid)
 return {"id":uid,"is_active":x.active}
@app.post("/api/forms",status_code=201)
def create_form(x:FormCreateRequest,u=Depends(management)):
 with get_db() as db:
  cur=db.execute("INSERT INTO form_templates (name,description,created_by) VALUES (?,?,?)",(x.name,x.description,u["id"])); fid=cur.lastrowid
  for n,f in enumerate(x.fields):
   if f.field_type not in FIELD_TYPES: raise HTTPException(400,"Invalid field type")
   if f.field_type=="select" and not f.options: raise HTTPException(400,"Select field needs options")
   db.execute("INSERT INTO form_fields (form_id,label,field_type,required,options_json,position) VALUES (?,?,?,?,?,?)",(fid,f.label,f.field_type,int(f.required),json.dumps(f.options),f.position if f.position else n))
  audit(db,u["id"],"form.created","form",fid); return {"id":fid,"name":x.name}
@app.get("/api/forms")
def forms(u=Depends(current)):
 with get_db() as db:r=db.execute("SELECT id,name,description,is_active,created_at FROM form_templates WHERE is_active=1 ORDER BY id DESC").fetchall()
 return [dict(x) for x in r]
@app.get("/api/forms/{fid}")
def form(fid:int,u=Depends(current)):
 with get_db() as db:
  f=db.execute("SELECT id,name,description,is_active FROM form_templates WHERE id=?",(fid,)).fetchone()
  if not f: raise HTTPException(404,"Form not found")
  fields=db.execute("SELECT id,label,field_type,required,options_json,position FROM form_fields WHERE form_id=? ORDER BY position,id",(fid,)).fetchall()
 return {"form":dict(f),"fields":[{**dict(x),"options":json.loads(x["options_json"])} for x in fields]}
@app.post("/api/forms/{fid}/entries",status_code=201)
def submit(fid:int,x:FormEntryRequest,u=Depends(current)):
 with get_db() as db:
  fields=db.execute("SELECT * FROM form_fields WHERE form_id=?",(fid,)).fetchall()
  if not fields: raise HTTPException(404,"Form not found")
  for f in fields:
   key=str(f["id"]); value=x.data.get(key)
   if f["required"] and (value is None or value==""): raise HTTPException(400,f"Required field missing: {f['label']}")
  cur=db.execute("INSERT INTO form_entries (form_id,user_id,data_json) VALUES (?,?,?)",(fid,u["id"],json.dumps(x.data))); eid=cur.lastrowid
  managers=db.execute("SELECT id FROM users WHERE role IN ('owner','admin','manager') AND is_active=1").fetchall()
  for m in managers:
   if m["id"]!=u["id"]: notify(db,m["id"],"Новая запись",f"{u['username']} отправил данные по форме")
  audit(db,u["id"],"form_entry.created","form_entry",eid)
 return {"id":eid,"status":"submitted"}
@app.get("/api/forms/{fid}/entries")
def entries(fid:int,u=Depends(current)):
 with get_db() as db:
  q="SELECT e.*,us.username FROM form_entries e JOIN users us ON us.id=e.user_id WHERE e.form_id=?"; args=[fid]
  if u["role"]=="worker": q+=" AND e.user_id=?";args.append(u["id"])
  q+=" ORDER BY e.id DESC"; r=db.execute(q,args).fetchall()
 return [{**dict(x),"data":json.loads(x["data_json"])} for x in r]
@app.put("/api/entries/{eid}/status")
def entry_status(eid:int,x:EntryStatusRequest,u=Depends(management)):
 if x.status not in {"submitted","reviewed","approved","rejected"}: raise HTTPException(400,"Invalid status")
 with get_db() as db:
  e=db.execute("SELECT user_id FROM form_entries WHERE id=?",(eid,)).fetchone()
  if not e: raise HTTPException(404,"Entry not found")
  db.execute("UPDATE form_entries SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(x.status,eid)); notify(db,e["user_id"],"Статус записи изменён",f"Новый статус: {x.status}"); audit(db,u["id"],"form_entry.status_changed","form_entry",eid)
 return {"id":eid,"status":x.status}
@app.get("/api/notifications")
def notifications(u=Depends(current)):
 with get_db() as db:r=db.execute("SELECT id,title,body,is_read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",(u["id"],)).fetchall()
 return [dict(x) for x in r]
@app.put("/api/notifications/{nid}/read")
def notification_read(nid:int,u=Depends(current)):
 with get_db() as db:
  cur=db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",(nid,u["id"]))
  if cur.rowcount!=1: raise HTTPException(404,"Notification not found")
 return {"id":nid,"is_read":True}
@app.post("/api/logout")
def logout(authorization:str|None=Header(default=None),u=Depends(current)):
 with get_db() as db: db.execute("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash=?",(token_hash(authorization[7:].strip()),));audit(db,u["id"],"account.logout","user",u["id"])
 return {"message":"Logged out"}
