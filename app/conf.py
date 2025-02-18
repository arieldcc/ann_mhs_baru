import sqlite3
import os
from flask import session

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Direktori untuk menyimpan file yang diunggah
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/uploads')
USER_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'user')
EXCEL_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'excel')  # Tambahkan folder untuk file Excel

DB_PATH = os.path.join(BASE_DIR, 'db', 'ann_mhsbaru.db')

# Buat folder utama jika belum ada
for folder in [UPLOAD_FOLDER, USER_UPLOAD_FOLDER, EXCEL_UPLOAD_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

def getConnectionDB():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        # cursor = conn.cursor()
        return conn
    except Exception as e:
        # print(f"Kesalahan : {e}")
        return f"Kesalahan : {e}"
    
def get_user_role():
    """Mengembalikan peran user dari sesi login"""
    return session.get('role', 'guest')  # Default ke 'guest' jika belum login
