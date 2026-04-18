from fastapi import FastAPI
from app.routers import threat_routes
# Import CORSMiddleware
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load .env untuk Supabase key
load_dotenv()

# Inisialisasi DB (buat tabel jika belum ada)
# init_db()

app = FastAPI(title="Threat Analytics API")

# ======================================================
# 🚀 KONFIGURASI CORS
# ======================================================

# Tentukan asal (origins) mana saja yang diizinkan untuk mengakses API Anda
origins = [
    # Izinkan frontend lokal Anda
    #"http://localhost",
    #"http://localhost:8080",
    #"http://192.168.33.91:8080",
    "http://10.100.21.235:8080",
    # Jika ada, tambahkan domain produksi frontend Anda di masa depan
    # "https://domain-frontend-anda.com", 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Daftar origins yang diizinkan
    allow_credentials=True, # Mengizinkan cookies, header otorisasi, dll.
    allow_methods=["*"],    # Mengizinkan semua metode (GET, POST, PUT, DELETE, dst.)
    allow_headers=["*"],    # Mengizinkan semua header
)

# ======================================================

app.include_router(threat_routes.router)

@app.get("/")
def read_root():
    return {"message": "Threat Analytics API is running 🚀"}