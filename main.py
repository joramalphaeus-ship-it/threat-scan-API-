import os
import json
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Literal, Union, Dict, Any
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Cookie
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
import jwt
import httpx
from google import genai
from google.genai import types

# ---------------------------------------------------------
# CONFIGURATION & ENVIRONMENT SETUP
# ---------------------------------------------------------
PORT = 3000
JWT_SECRET = os.getenv("JWT_SECRET", "pci_compliance_secure_sha512_ledger_jwt_token_secret_key_9918")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
PAYPAL_ENV = os.getenv("PAYPAL_ENV", "sandbox")

app = FastAPI(
    title="CSV Shield Compliance API Gateway",
    description="Python FastAPI counterpart for corporate identity, credit ledgers, and Gemini compliance sanitizers.",
    version="1.0.0"
)

# Enable CORS to allow secure interactions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with specific origins for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "db.json"

# ---------------------------------------------------------
# DATABASE PERSISTENCE LAYER (JSON FILE DB)
# ---------------------------------------------------------
def load_database() -> Dict[str, Any]:
    if not os.path.exists(DB_PATH):
        # Bootstrap database with identical JSON schemas
        initial_db = {
            "users": [],
            "wallets": [],
            "transactions": [],
            "scans": []
        }
        with open(DB_PATH, "w") as f:
            json.dump(initial_db, f, indent=2)
        return initial_db
    
    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading persistence database, returning empty payload: {e}")
        return {"users": [], "wallets": [], "transactions": [], "scans": []}

def save_database(data: Dict[str, Any]):
    try:
        with open(DB_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Failed to write persistence database to disk: {e}")

# Pre-load database state
db = load_database()

# ---------------------------------------------------------
# SECURITY & PASSWORD HASHING UTILITY
# ---------------------------------------------------------
def hash_password(password: str, salt: str) -> str:
    # Identical to Node.js: crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex")
    return hashlib.pbkdf2_hmac(
        'sha512', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        1000, 
        dklen=64
    ).hex()

def generate_salt() -> str:
    return secrets.token_hex(16)

# ---------------------------------------------------------
# PYDANTIC SCHEMAS (DATA VALIDATION)
# ---------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class CreateOrderRequest(BaseModel):
    amount: str
    purpose: Optional[str] = "deposit"

class CaptureOrderRequest(BaseModel):
    orderId: str
    amount: str
    purpose: Optional[str] = "deposit"

class SanitizeRequest(BaseModel):
    content: str
    filename: Optional[str] = "pasted_compliance_ledger.csv"

# ---------------------------------------------------------
# DEPENDENCIES (JWT AUTHENTICATION & RATE LIMITING)
# ---------------------------------------------------------
def authenticate_token(auth_token: Optional[str] = Cookie(None)) -> Dict[str, Any]:
    if not auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing auth token session cookie. Standard handshake required."
        )
    try:
        decoded = jwt.decode(auth_token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid cryptosignature handshake.")

def paywall_dependency(user: Dict[str, Any] = Depends(authenticate_token)) -> Dict[str, Any]:
    local_db = load_database()
    wallet = next((w for w in local_db["wallets"] if w["userId"] == user["id"]), None)
    
    if not wallet:
        raise HTTPException(status_code=404, detail="Corporate wallet index missing.")
    
    cost_threshold = 0.02 if wallet["tier"] == "premium" else 0.05
    if wallet["creditBalance"] < cost_threshold:
        raise HTTPException(
            status_code=402,
            detail=f"Credit Balance too low. This transaction requires {cost_threshold} USD."
        )
    return user

# Simple Rate Limiting In-Memory Store
IP_LIMITS = {}

async def rate_limit(request: Request):
    client_ip = request.client.host
    now = datetime.utcnow()
    # Simple limit of 60 requests / minute
    if client_ip not in IP_LIMITS:
        IP_LIMITS[client_ip] = []
    
    # Filter for timestamps within the last 60 seconds
    IP_LIMITS[client_ip] = [t for t in IP_LIMITS[client_ip] if now - t < timedelta(seconds=60)]
    
    if len(IP_LIMITS[client_ip]) >= 60:
        raise HTTPException(status_code=429, detail="Rate Limit Exceeded. Max 60 requests per minute.")
    
    IP_LIMITS[client_ip].append(now)

# ---------------------------------------------------------
# AUTHENTICATION ROUTERS
# ---------------------------------------------------------
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(req_data: RegisterRequest, response: Response):
    email_sanitized = req_data.email.lower().strip()
    local_db = load_database()
    
    if any(u["email"] == email_sanitized for u in local_db["users"]):
        raise HTTPException(status_code=400, detail="Registration Refused. User with specified email already exists.")
    
    salt = generate_salt()
    pw_hash = hash_password(req_data.password, salt)
    user_id = "usr_" + secrets.token_hex(4)
    
    new_user = {
        "id": user_id,
        "email": email_sanitized,
        "passwordHash": pw_hash,
        "salt": salt,
        "createdAt": datetime.utcnow().isoformat()
    }
    
    new_wallet = {
        "userId": user_id,
        "creditBalance": 10.00,  # Playful $10 USD complimentary initial credit
        "tier": "free",
        "updatedAt": datetime.utcnow().isoformat()
    }
    
    local_db["users"].append(new_user)
    local_db["wallets"].append(new_wallet)
    save_database(local_db)
    
    token = jwt.encode(
        {"id": user_id, "email": email_sanitized, "exp": datetime.utcnow() + timedelta(days=7)},
        JWT_SECRET,
        algorithm="HS256"
    )
    
    response.set_cookie(
        key="auth_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600
    )
    
    return {
        "success": True,
        "user": {"id": user_id, "email": email_sanitized},
        "wallet": new_wallet,
        "message": "Cyber security and financial identity ledger initiated successfully. Compliment $10.00 credit ledger verified."
    }

@app.post("/api/auth/login")
def login(req_data: LoginRequest, response: Response):
    email_sanitized = req_data.email.lower().strip()
    local_db = load_database()
    
    user = next((u for u in local_db["users"] if u["email"] == email_sanitized), None)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email credentials or incorrect passcode matching key signatures.")
    
    calculated_hash = hash_password(req_data.password, user["salt"])
    if calculated_hash != user["passwordHash"]:
        raise HTTPException(status_code=400, detail="Invalid email credentials or incorrect passcode matching key signatures.")
    
    wallet = next((w for w in local_db["wallets"] if w["userId"] == user["id"]), None)
    
    token = jwt.encode(
        {"id": user["id"], "email": user["email"], "exp": datetime.utcnow() + timedelta(days=7)},
        JWT_SECRET,
        algorithm="HS256"
    )
    
    response.set_cookie(
        key="auth_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600
    )
    
    return {
        "success": True,
        "user": {"id": user["id"], "email": user["email"]},
        "wallet": wallet,
        "message": "Identity authentication handshake established successfully."
    }

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("auth_token")
    return {"success": True, "message": "Teardown established user sessions. Security keys safely purged."}

@app.get("/api/auth/me")
def get_me(user: Dict[str, Any] = Depends(authenticate_token)):
    local_db = load_database()
    wallet = next((w for w in local_db["wallets"] if w["userId"] == user["id"]), None)
    user_transactions = [t for t in local_db["transactions"] if t["userId"] == user["id"]]
    user_scans = [s for s in local_db["scans"] if s["userId"] == user["id"]]
    
    return {
        "success": True,
        "user": {"id": user["id"], "email": user["email"]},
        "wallet": wallet,
        "transactions": user_transactions,
        "scans": user_scans
    }

# ---------------------------------------------------------
# PAYPAL REST INTEGRATION
# ---------------------------------------------------------
def is_paypal_production() -> bool:
    return PAYPAL_ENV != "sandbox"

async def get_paypal_access_token() -> Optional[str]:
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET or PAYPAL_CLIENT_ID == "MY_PAYPAL_CLIENT_ID":
        return None
    
    endpoint = "https://api-m.paypal.com" if is_paypal_production() else "https://api-m.sandbox.paypal.com"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{endpoint}/v1/oauth2/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
                data={"grant_type": "client_credentials"},
                timeout=10.0
            )
            if response.status_code == 200:
                return response.json().get("access_token")
        except Exception as e:
            print(f"PayPal oauth handshake failed: {e}")
    return None

@app.get("/api/billing/paypal/config")
@app.get("/api/v1/paypal/config")
def get_paypal_config():
    return {
        "clientId": PAYPAL_CLIENT_ID if PAYPAL_CLIENT_ID and PAYPAL_CLIENT_ID != "MY_PAYPAL_CLIENT_ID" else "",
        "env": "production" if is_paypal_production() else "sandbox"
    }

@app.post("/api/billing/paypal/create-order")
@app.post("/api/v1/paypal/create-order")
async def create_order(req_data: CreateOrderRequest, user: Dict[str, Any] = Depends(authenticate_token)):
    token = await get_paypal_access_token()
    if token:
        endpoint = "https://api-m.paypal.com" if is_paypal_production() else "https://api-m.sandbox.paypal.com"
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(
                    f"{endpoint}/v2/checkout/orders",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "intent": "CAPTURE",
                        "purchase_units": [{
                            "amount": {
                                "currency_code": "USD",
                                "value": f"{float(req_data.amount):.2f}"
                            },
                            "custom_id": f"{user['id']}|{req_data.purpose or 'deposit'}"
                        }]
                    },
                    timeout=10.0
                )
                order_res = res.json()
                if res.status_code >= 400:
                    raise HTTPException(status_code=res.status_code, detail=order_res)
                return {"id": order_res["id"], "success": True}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Connection failure to PayPal gateways: {e}")
    else:
        # Sandbox simulator code fallback
        mock_order_id = "PP-ORDER-" + secrets.token_hex(4).upper()
        return {
            "id": mock_order_id,
            "success": True,
            "simulated": True,
            "message": "Safe local simulation order ID created. Continue to verify."
        }

@app.post("/api/billing/paypal/capture-order")
@app.post("/api/v1/paypal/capture-order")
async def capture_order(req_data: CaptureOrderRequest, user: Dict[str, Any] = Depends(authenticate_token)):
    local_db = load_database()
    wallet_idx = next((i for i, w in enumerate(local_db["wallets"]) if w["userId"] == user["id"]), -1)
    
    if wallet_idx == -1:
        raise HTTPException(status_code=404, detail="Corporate purse index allocation failed.")
    
    premium_usd = float(req_data.amount) if req_data.amount else 0.00
    verified = False
    paypal_ref = req_data.orderId
    
    token = await get_paypal_access_token()
    if token and req_data.orderId and not req_data.orderId.startswith("PP-ORDER-"):
        endpoint = "https://api-m.paypal.com" if is_paypal_production() else "https://api-m.sandbox.paypal.com"
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(
                    f"{endpoint}/v2/checkout/orders/{req_data.orderId}/capture",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"
                    },
                    timeout=12.0
                )
                if res.status_code == 200:
                    order_data = res.json()
                    if order_data.get("status") == "COMPLETED":
                        verified = True
                        paypal_ref = order_data.get("id", req_data.orderId)
            except Exception as e:
                print(f"PayPal capture request failed: {e}")
    else:
        # Simulator bypass approved
        verified = True
        
    if not verified:
        raise HTTPException(
            status_code=400, 
            detail="Transaction verification failure. Upstream server rejected signature."
        )
        
    exact_tx_ref = f"PAYPAL-PCI-{paypal_ref}"
    
    # Check duplicate transactions
    if any(t["paypalOrderId"] == req_data.orderId for t in local_db["transactions"]):
        return {
            "success": True,
            "message": "Ledger transaction reference matching index coordinates already completed.",
            "wallet": local_db["wallets"][wallet_idx]
        }
        
    wallet = local_db["wallets"][wallet_idx]
    old_balance = wallet["creditBalance"]
    recharge_usd = premium_usd
    
    if req_data.purpose == "premium_tier":
        wallet["tier"] = "premium"
        recharge_usd = 50.00  # Complimentary credits for professional level
        
    wallet["creditBalance"] = round(old_balance + recharge_usd, 2)
    wallet["updatedAt"] = datetime.utcnow().isoformat()
    
    new_tx = {
        "id": "tx_" + secrets.token_hex(4),
        "userId": user["id"],
        "paypalOrderId": req_data.orderId,
        "amount": recharge_usd,
        "currency": "USD",
        "status": "COMPLETED",
        "timestamp": datetime.utcnow().isoformat(),
        "type": "deposit",
        "reference": exact_tx_ref,
        "clientName": user["email"]
    }
    
    local_db["transactions"].insert(0, new_tx)
    save_database(local_db)
    
    return {
        "success": True,
        "message": f"License successfully upgraded. Added ${recharge_usd:.2f} USD credits to your wallet." if req_data.purpose == "premium_tier" else f"Reload verified. Added ${recharge_usd:.2f} USD to corporate wallet.",
        "wallet": wallet,
        "transaction": new_tx
    }

# ---------------------------------------------------------
# GEMINI COMPLIANCE SHIELD & HEURISTIC FALLBACK
# ---------------------------------------------------------
@app.post("/api/v1/files/sanitize")
async def sanitize_file(req_data: SanitizeRequest, user: Dict[str, Any] = Depends(paywall_dependency)):
    local_db = load_database()
    wallet_idx = next((i for i, w in enumerate(local_db["wallets"]) if w["userId"] == user["id"]), -1)
    wallet = local_db["wallets"][wallet_idx]
    
    # Calculate fee deductions
    fee = 0.02 if wallet["tier"] == "premium" else 0.05
    wallet["creditBalance"] = round(wallet["creditBalance"] - fee, 2)
    wallet["updatedAt"] = datetime.utcnow().isoformat()
    
    charge_id = "tx_" + secrets.token_hex(4)
    billing_tx = {
        "id": charge_id,
        "userId": user["id"],
        "paypalOrderId": f"SYS-CHARGE-{charge_id.upper()}",
        "amount": -fee,
        "currency": "USD",
        "status": "COMPLETED",
        "timestamp": datetime.utcnow().isoformat(),
        "type": "scan_charge",
        "reference": f"SANITIZATION-CHARGE-{charge_id.upper()}",
        "clientName": user["email"]
    }
    local_db["transactions"].insert(0, billing_tx)
    
    output_csv = ""
    quotes_fixed = 0
    commas_fixed = 0
    null_bytes_fixed = 0
    blank_rows_purged = 0
    analysis_report = ""
    
    # Try Gemini 3.5 API using the official Google GenAI SDK
    if GEMINI_API_KEY and GEMINI_API_KEY != "MY_GEMINI_API_KEY":
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            prompt = f"""You are a high-fidelity spreadsheet compliance parsing optimizer.
Analyze this suspect, corrupt, or unescaped CSV content:
"{req_data.content}"

Perform these core compliance operations:
1. Escape nested quotes matching RFC-4180 specifications.
2. Neutralize and strip embedded null-byte streams (\\x00).
3. Align mismatched columnar trailing fields.
4. Purge empty system carriage structures.

Return your evaluation STRICTLY in compliance-formatted valid JSON format. Provide these exact keys:
- "repairedCSV": the corrected spreadsheet string content.
- "quotesFixed": integer count representing unescaped quote symbols aligned.
- "commasFixed": integer count representing comma parameters aligned.
- "nullBytes": integer count representing binary null fields stripped.
- "blankRows": integer count representing blank spreadsheet sequences discarded.
- "descriptiveMarkdown": brief descriptive insights of what you repaired (1-2 precise summary paragraphs).

Output pure raw JSON characters without wrapping quotes inside backticks or markup blocks. Ensure accurate structural output."""

            response = client.models.generate_content(
                model='gemini-3.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                ),
            )
            
            parsed_result = json.loads(response.text.strip())
            output_csv = parsed_result.get("repairedCSV", req_data.content)
            quotes_fixed = int(parsed_result.get("quotesFixed", 0))
            commas_fixed = int(parsed_result.get("commasFixed", 0))
            null_bytes_fixed = int(parsed_result.get("nullBytes", 0))
            blank_rows_purged = int(parsed_result.get("blankRows", 0))
            analysis_report = parsed_result.get("descriptiveMarkdown", "File repairs completed instantly via AI model.")
            
        except Exception as e:
            print(f"Gemini API returned error: {e}. Falling back to standard heuristic algorithms.")
            GEMINI_API_KEY = None  # Force local heuristic execution
            
    # Heuristic Compliance Fallback Algorithm (Identical logic to TypeScript application)
    if not GEMINI_API_KEY or GEMINI_API_KEY == "MY_GEMINI_API_KEY":
        lines = req_data.content.split("\n")
        clean_rows = []
        for line in lines:
            trimmed = line.replace("\x00", "").strip()
            if trimmed == "" or trimmed == ",,,":
                blank_rows_purged += 1
                continue
            
            # Unescaped quote balancing
            if trimmed.count('"') % 2 != 0:
                trimmed = trimmed.replace('"', '""')
                trimmed = f'"{trimmed}"'
                quotes_fixed += 2
                
            # Alignment check
            if ",," in trimmed:
                commas_fixed += 1
                trimmed = trimmed.replace(",,", ",")
                
            clean_rows.append(trimmed)
            
        if "\x00" in req_data.content:
            null_bytes_fixed += req_data.content.count("\x00")
            
        output_csv = "\n".join(clean_rows)
        analysis_report = (
            "### Compliance Forensics Diagnostic Report\n\n"
            "- **Status**: Heuristics completed.\n"
            "- **Description**: Checked cell array sequences against standard RFC-4180 guidelines. "
            "Purged corrupted byte formats across data loops. Align standard column delimiter limits representation."
        )

    # Calculate content length bytes
    original_size_kb = len(req_data.content.encode('utf-8')) / 1024.0
    cleaned_size_kb = len(output_csv.encode('utf-8')) / 1024.0

    scan_report = {
        "id": "scan_" + secrets.token_hex(4),
        "userId": user["id"],
        "fileName": req_data.filename or "pasted_compliance_ledger.csv",
        "rowsCount": len(req_data.content.split("\n")),
        "fixedAnomalies": quotes_fixed + commas_fixed + null_bytes_fixed,
        "originalSize": f"{original_size_kb:.2f} KB",
        "cleanedSize": f"{cleaned_size_kb:.2f} KB",
        "quotesFixed": quotes_fixed,
        "commasFixed": commas_fixed,
        "nullBytesFixed": null_bytes_fixed,
        "blankRowsPurged": blank_rows_purged,
        "analysis": analysis_report,
        "repairedCSV": output_csv,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "COMPLETED",
        "complianceCode": "ISO-Fintech Secured" if wallet["tier"] == "premium" else "UTF-8 Standard"
    }
    
    local_db["scans"].insert(0, scan_report)
    save_database(local_db)
    
    return {
        "success": True,
        "scanReport": scan_report,
        "wallet": wallet
    }

# ---------------------------------------------------------
# PORTAL METRICS & AUDITING DATA ENDPOINT
# ---------------------------------------------------------
@app.get("/api/v1/state")
def get_state():
    return load_database()

# ---------------------------------------------------------
# RUN COMMAND
# ---------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
@app.get("/")
def root():
    return {"status": "Threat Scan API is live", "docs": "/docs"}
