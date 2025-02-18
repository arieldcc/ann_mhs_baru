from flask import render_template, request, flash, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from app import app
import pandas as pd
import numpy as np
import json
import os
import bcrypt
import datetime
from app.conf import getConnectionDB, get_user_role, EXCEL_UPLOAD_FOLDER, USER_UPLOAD_FOLDER
import logging
# library ANN
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam, SGD, RMSprop
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import seaborn as sns

logging.basicConfig(level=logging.DEBUG)

# Tambahkan secret key agar session bisa digunakan
app.secret_key = "anNFikom2025"  # Gantilah dengan sesuatu yang unik dan rahasia

# Middleware untuk memastikan pengguna login
@app.before_request
def check_login():
    allowed_routes = ['signin', 'static']
    if 'username' not in session and request.endpoint not in allowed_routes:
        return redirect(url_for('signin'))
    
# Middleware untuk membatasi akses berdasarkan role
def role_required(allowed_roles):
    def wrapper(f):
        def decorated_function(*args, **kwargs):
            role = get_user_role()
            if role not in allowed_roles:
                flash("Anda tidak memiliki izin untuk mengakses halaman ini!", "danger")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return wrapper

# Halaman login
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = getConnectionDB()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role, foto FROM t_user WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user[2]):  # Cocokkan password hash
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]  # Simpan role di sesi
            session['foto'] = user[4] if user[4] else None  # Simpan foto jika ada
            flash("Login berhasil!", "success")
            return redirect(url_for('index'))
        else:
            flash("Username atau password salah!", "danger")

    return render_template('signin.html')

# Logout user
@app.route('/logout')
def logout():
    session.clear()
    flash("Anda telah logout!", "success")
    return redirect(url_for('signin'))

# halaman utama
@app.route('/')
def index():
    return render_template('home.html')

# coba menu data
@app.route('/data')
def data():
    return render_template('data.html')

# bagian user-useran lah
@app.route('/list_user')
@role_required(['admin', 'pimpinan'])
def list_user():
    conn = getConnectionDB()
    cursor = conn.cursor()
    
    # Ambil data user dengan foto, email, dan created_at
    cursor.execute("SELECT id, username, email, role, foto, created_at FROM t_user")
    users = cursor.fetchall()
    conn.close()

    # Konversi hasil query ke list of dictionaries
    users_list = []
    for row in users:
        users_list.append({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'role': row[3],
            'foto': row[4],
            'created_at': row[5]  # Format tanggal akan dilakukan di template
        })

    return render_template('list_user.html', users=users_list)

# form input user
@app.route('/input_user', methods=['GET', 'POST'])
@role_required(['admin'])
def input_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        re_password = request.form['re_password']
        role = request.form['role']
        foto = request.files['foto']

        if len(username) < 8:
            flash("Username minimal 8 karakter!", "warning")
            return redirect(url_for('input_user'))

        if "@" not in email:
            flash("Email tidak valid!", "warning")
            return redirect(url_for('input_user'))

        if len(password) < 8:
            flash("Password minimal 8 karakter!", "warning")
            return redirect(url_for('input_user'))

        if password != re_password:
            flash("Password dan Re-Password tidak cocok!", "error")
            return redirect(url_for('input_user'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Buat folder khusus untuk user
        user_folder = os.path.join(USER_UPLOAD_FOLDER, username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        foto_filename = None
        if foto and foto.filename:
            foto_filename = secure_filename(foto.filename)
            foto_path = os.path.join(user_folder, foto_filename)
            foto.save(foto_path)

        created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = getConnectionDB()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO t_user (username, email, password, role, foto, created_at) VALUES (?, ?, ?, ?, ?, ?)", 
                           (username, email, hashed_password, role, foto_filename, created_at))
            conn.commit()
            flash("User berhasil ditambahkan!", "success")
        except Exception as e:
            flash(f"Gagal menambahkan user: {e}", "error")
        finally:
            conn.close()

        return redirect(url_for('list_user'))

    return render_template('input_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@role_required(['admin'])
def edit_user(user_id):
    conn = getConnectionDB()
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, email, role, foto FROM t_user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User tidak ditemukan!", "error")
        return redirect(url_for('list_user'))

    user_data = {
        'id': user[0],
        'username': user[1],
        'email': user[2],
        'role': user[3],
        'foto': user[4]
    }

    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']
        re_password = request.form['re_password']
        foto = request.files['foto']
        
        if len(username) < 8:
            flash("Username minimal 8 karakter!", "warning")
            return redirect(url_for('edit_user', user_id=user_id))

        if "@" not in email:
            flash("Email tidak valid!", "warning")
            return redirect(url_for('edit_user', user_id=user_id))

        if password:
            if len(password) < 8:
                flash("Password minimal 8 karakter!", "warning")
                return redirect(url_for('edit_user', user_id=user_id))

            if password != re_password:
                flash("Password dan Re-Password tidak cocok!", "error")
                return redirect(url_for('edit_user', user_id=user_id))

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        else:
            hashed_password = None

        foto_filename = user_data['foto']
        if foto and foto.filename:
            user_folder = os.path.join(USER_UPLOAD_FOLDER, username)
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)

            foto_filename = secure_filename(foto.filename)
            foto_path = os.path.join(user_folder, foto_filename)

            if user_data['foto']:
                old_foto_path = os.path.join(USER_UPLOAD_FOLDER, user_data['username'], user_data['foto'])
                if os.path.exists(old_foto_path):
                    os.remove(old_foto_path)

            foto.save(foto_path)

        updated_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        try:
            if hashed_password:
                cursor.execute("""
                    UPDATE t_user 
                    SET username = ?, email = ?, password = ?, role = ?, foto = ?, updated_at = ?
                    WHERE id = ?
                """, (username, email, hashed_password, role, foto_filename, updated_at, user_id))
            else:
                cursor.execute("""
                    UPDATE t_user 
                    SET username = ?, email = ?, role = ?, foto = ?, updated_at = ?
                    WHERE id = ?
                """, (username, email, role, foto_filename, updated_at, user_id))

            conn.commit()
            flash("User berhasil diperbarui!", "success")
        except Exception as e:
            flash(f"Gagal mengupdate user: {e}", "error")
        finally:
            conn.close()

        return redirect(url_for('list_user'))

    return render_template('edit_user.html', user=user_data)

@app.route('/delete_user/<int:user_id>', methods=['GET'])
@role_required(['admin'])
def delete_user(user_id):
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Cek apakah user ada
    cursor.execute("SELECT username, foto FROM t_user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User tidak ditemukan!", "error")
        return redirect(url_for('list_user'))

    username, foto_filename = user

    # Hapus foto user jika ada
    user_folder = os.path.join(USER_UPLOAD_FOLDER, username)
    if foto_filename:
        foto_path = os.path.join(user_folder, foto_filename)
        if os.path.exists(foto_path):
            os.remove(foto_path)

    # Hapus folder user jika kosong
    if os.path.exists(user_folder) and not os.listdir(user_folder):
        os.rmdir(user_folder)

    # Hapus user dari database
    try:
        cursor.execute("DELETE FROM t_user WHERE id = ?", (user_id,))
        conn.commit()
        flash("User berhasil dihapus!", "success")
    except Exception as e:
        flash(f"Gagal menghapus user: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('list_user'))

# halaman profil
@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('signin'))

    username = session['username']

    conn = getConnectionDB()
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, role, foto, created_at, updated_at FROM t_user WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        user_data = {
            'username': user[0],
            'email': user[1],
            'role': user[2],
            'foto': user[3],
            'created_at': user[4],
            'updated_at': user[5] if user[5] else 'Belum diperbarui'
        }
    else:
        user_data = {}

    return render_template('profile.html', user=user_data)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('signin'))

    username = session['username']

    conn = getConnectionDB()
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, role, foto FROM t_user WHERE username = ?", (username,))
    user = cursor.fetchone()

    if request.method == 'POST':
        new_email = request.form['email']
        new_foto = request.files['foto']

        foto_filename = user[3]  # Foto lama tetap digunakan jika tidak diubah

        if new_foto and new_foto.filename:
            foto_filename = secure_filename(new_foto.filename)
            user_folder = os.path.join('static/uploads/user/', username)
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)
            new_foto.save(os.path.join(user_folder, foto_filename))

        updated_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        cursor.execute("UPDATE t_user SET email = ?, foto = ?, updated_at = ? WHERE username = ?", (new_email, foto_filename, updated_at, username))
        conn.commit()
        conn.close()

        session['foto'] = foto_filename  # Update session foto

        flash("Profil berhasil diperbarui!", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user={'username': user[0], 'email': user[1], 'foto': user[3]})

# Bagian Data:
@app.route('/dataset')
@role_required(['admin'])
def dataset():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data dari tabel t_data, diurutkan berdasarkan kode_prodi
    cursor.execute("SELECT id, kode_prodi, nama_prodi, jenjang, tahun, variabel FROM t_data ORDER BY kode_prodi, tahun")
    data = cursor.fetchall()
    
    # Konversi hasil query ke list of dictionaries
    dataset = []
    for row in data:
        dataset.append({
            'id': row[0],
            'kode_prodi': row[1],
            'nama_prodi': row[2],
            'jenjang': row[3],
            'tahun': row[4],
            'variabel': json.loads(row[5])  # Konversi JSON string ke dict
        })

    conn.close()
    return render_template('dataset.html', dataset=dataset)

# input dataset:
@app.route('/upload_data', methods=['GET', 'POST'])
@role_required(['admin'])
def upload_data():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("Tidak ada file yang dipilih!", "danger")
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash("Pilih file terlebih dahulu!", "danger")
            return redirect(request.url)

        # Simpan file ke folder uploads/excel
        filename = secure_filename(file.filename)
        file_path = os.path.join(EXCEL_UPLOAD_FOLDER, filename)
        file.save(file_path)

        try:
            # Membaca file Excel
            df = pd.read_excel(file_path, engine='openpyxl')

            # Validasi apakah kolom yang diperlukan ada di file Excel
            required_columns = {'kode_prodi', 'nama_prodi', 'jenjang', 'tahun', 'target', 'daftar', 'daftar_ulang'}
            if not required_columns.issubset(df.columns):
                flash("Format file tidak sesuai!", "danger")
                return redirect(request.url)

            # Simpan data ke session agar bisa ditampilkan sebelum simpan
            session['preview_data'] = df.to_dict(orient='records')

            flash("Data berhasil diunggah! Silakan pilih data yang ingin disimpan.", "info")
            return redirect(url_for('preview_data'))

        except Exception as e:
            flash(f"Terjadi kesalahan: {str(e)}", "danger")
            return redirect(request.url)

    return render_template('upload_data.html')

# validasi dataset yang akan diinput:
@app.route('/preview_data', methods=['GET', 'POST'])
@role_required(['admin'])
def preview_data():
    data = session.get('preview_data', [])

    if request.method == 'POST':
        selected_ids = request.form.getlist('selected_data')

        if not selected_ids:
            flash("Tidak ada data yang dipilih untuk disimpan!", "danger")
            return redirect(url_for('preview_data'))

        conn = getConnectionDB()
        cursor = conn.cursor()

        try:
            for index in selected_ids:
                row = data[int(index)]  # Ambil data berdasarkan index yang dipilih
                variabel_json = json.dumps({
                    "target": row["target"],
                    "daftar": row["daftar"],
                    "daftar_ulang": row["daftar_ulang"]
                })

                # Cek apakah data sudah ada berdasarkan kode_prodi & tahun
                cursor.execute("""
                    SELECT id FROM t_data WHERE kode_prodi = ? AND tahun = ?
                """, (row["kode_prodi"], row["tahun"]))

                existing_data = cursor.fetchone()

                if existing_data:
                    # Jika sudah ada, lakukan update
                    cursor.execute("""
                        UPDATE t_data 
                        SET nama_prodi = ?, jenjang = ?, variabel = ? 
                        WHERE kode_prodi = ? AND tahun = ?
                    """, (row["nama_prodi"], row["jenjang"], variabel_json, row["kode_prodi"], row["tahun"]))
                else:
                    # Jika belum ada, lakukan insert
                    cursor.execute("""
                        INSERT INTO t_data (kode_prodi, nama_prodi, jenjang, tahun, variabel) 
                        VALUES (?, ?, ?, ?, ?)
                    """, (row["kode_prodi"], row["nama_prodi"], row["jenjang"], row["tahun"], variabel_json))

            conn.commit()
            flash("Data berhasil disimpan!", "success")
            return redirect(url_for('dataset'))

        except Exception as e:
            flash(f"Terjadi kesalahan saat menyimpan data: {str(e)}", "danger")
            return redirect(url_for('preview_data'))
        finally:
            conn.close()

    return render_template('upload_preview.html', data=data)

# edit data:
@app.route('/edit_data/<int:data_id>', methods=['GET', 'POST'])
@role_required(['admin'])
def edit_data(data_id):
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data berdasarkan ID
    cursor.execute("SELECT id, kode_prodi, nama_prodi, jenjang, tahun, variabel FROM t_data WHERE id = ?", (data_id,))
    row = cursor.fetchone()

    if not row:
        flash("Data tidak ditemukan!", "danger")
        return redirect(url_for('dataset'))

    data = {
        'id': row[0],
        'kode_prodi': row[1],
        'nama_prodi': row[2],
        'jenjang': row[3],
        'tahun': row[4],
        'variabel': json.loads(row[5])  # Konversi JSON string ke dict
    }

    if request.method == 'POST':
        target = request.form['target']
        daftar = request.form['daftar']
        daftar_ulang = request.form['daftar_ulang']

        # Simpan perubahan
        variabel_json = json.dumps({
            "target": target,
            "daftar": daftar,
            "daftar_ulang": daftar_ulang
        })

        cursor.execute("""
            UPDATE t_data 
            SET variabel = ? WHERE id = ?
        """, (variabel_json, data_id))

        conn.commit()
        conn.close()

        flash("Data berhasil diperbarui!", "success")
        return redirect(url_for('dataset'))

    return render_template('edit_data.html', data=data)

# hapus data:
@app.route('/delete_data/<int:data_id>')
@role_required(['admin'])
def delete_data(data_id):
    conn = getConnectionDB()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM t_data WHERE id = ?", (data_id,))
        conn.commit()
        flash("Data berhasil dihapus!", "success")
    except Exception as e:
        flash(f"Terjadi kesalahan saat menghapus data: {str(e)}", "danger")
    finally:
        conn.close()

    return redirect(url_for('dataset'))

# visualisasi data:
@app.route('/visualisasi/ti')
@role_required(['admin', 'pimpinan'])
def visualisasi_ti():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data Teknik Informatika (kode_prodi = 55201) urutkan berdasarkan tahun
    cursor.execute("""
        SELECT tahun, variabel FROM t_data 
        WHERE kode_prodi = '55201' 
        ORDER BY tahun
    """)
    data = cursor.fetchall()
    conn.close()

    # Siapkan data untuk grafik
    tahun = []
    target = []
    daftar = []
    daftar_ulang = []

    for row in data:
        tahun.append(row[0])  # Tahun
        variabel = json.loads(row[1])  # Konversi JSON

        target.append(variabel.get("target", 0))  # Target Mahasiswa
        daftar.append(variabel.get("daftar", 0))  # Mahasiswa Mendaftar
        daftar_ulang.append(variabel.get("daftar_ulang", 0))  # Mahasiswa Daftar Ulang

    return render_template('visualisasi_ti.html', 
                           tahun=tahun, 
                           target=target, 
                           daftar=daftar, 
                           daftar_ulang=daftar_ulang)

@app.route('/visualisasi/si')
@role_required(['admin', 'pimpinan'])
def visualisasi_si():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data untuk Sistem Informasi (kode_prodi = 57201), urutkan berdasarkan tahun
    cursor.execute("""
        SELECT tahun, variabel FROM t_data 
        WHERE kode_prodi = '57201' 
        ORDER BY tahun
    """)
    data = cursor.fetchall()
    conn.close()

    # Siapkan data untuk grafik
    tahun = []
    target = []
    daftar = []
    daftar_ulang = []

    for row in data:
        tahun.append(row[0])  # Tahun
        variabel = json.loads(row[1])  # Konversi JSON
        target.append(variabel.get("target", 0))  
        daftar.append(variabel.get("daftar", 0))  
        daftar_ulang.append(variabel.get("daftar_ulang", 0))  

    return render_template('visualisasi_si.html', tahun=tahun, target=target, daftar=daftar, daftar_ulang=daftar_ulang)

@app.route('/visualisasi/dkv')
@role_required(['admin', 'pimpinan'])
def visualisasi_dkv():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data untuk Desain Komunikasi Visual (kode_prodi = 90241), urutkan berdasarkan tahun
    cursor.execute("""
        SELECT tahun, variabel FROM t_data 
        WHERE kode_prodi = '90241' 
        ORDER BY tahun
    """)
    data = cursor.fetchall()
    conn.close()

    # Siapkan data untuk grafik
    tahun = []
    target = []
    daftar = []
    daftar_ulang = []

    for row in data:
        tahun.append(row[0])  # Tahun
        variabel = json.loads(row[1])  # Konversi JSON
        target.append(variabel.get("target", 0))  
        daftar.append(variabel.get("daftar", 0))  
        daftar_ulang.append(variabel.get("daftar_ulang", 0))  

    return render_template('visualisasi_dkv.html', tahun=tahun, target=target, daftar=daftar, daftar_ulang=daftar_ulang)

@app.route('/visualisasi/fakultas')
@role_required(['admin', 'pimpinan'])
def visualisasi_fakultas():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data semua prodi, urutkan berdasarkan tahun
    cursor.execute("""
        SELECT kode_prodi, nama_prodi, tahun, variabel FROM t_data 
        ORDER BY tahun, kode_prodi
    """)
    data = cursor.fetchall()

    conn.close()

    # Siapkan struktur data untuk grafik
    prodi_dict = {}
    tahun_labels = set()

    for row in data:
        kode_prodi = row[0]
        nama_prodi = row[1]
        tahun = row[2]
        variabel = json.loads(row[3])  # Konversi JSON

        tahun_labels.add(tahun)

        if kode_prodi not in prodi_dict:
            prodi_dict[kode_prodi] = {
                "nama_prodi": nama_prodi,
                "daftar_ulang": {}
            }

        prodi_dict[kode_prodi]["daftar_ulang"][tahun] = variabel.get("daftar_ulang", 0)

    # Urutkan tahun
    tahun_labels = sorted(tahun_labels)

    # Format data untuk Chart.js
    datasets = []
    for kode_prodi, prodi in prodi_dict.items():
        daftar_ulang = [prodi["daftar_ulang"].get(t, 0) for t in tahun_labels]
        datasets.append({
            "label": prodi["nama_prodi"],
            "data": daftar_ulang,
            "backgroundColor": f"rgba({hash(kode_prodi) % 255}, {hash(prodi['nama_prodi']) % 255}, 200, 0.7)",
            "borderColor": f"rgba({hash(kode_prodi) % 255}, {hash(prodi['nama_prodi']) % 255}, 200, 1)",
            "borderWidth": 1
        })

    return render_template('visualisasi_fakultas.html', tahun_labels=tahun_labels, datasets=datasets)

# Proses Prediksi Prodi Teknik Informatika
def minmax_scaling(data, new_min=-1, new_max=1):
    """Fungsi untuk melakukan normalisasi Min-Max Scaling"""
    minA = np.min(data)
    maxA = np.max(data)
    return [(new_max - new_min) * (v - minA) / (maxA - minA) + new_min for v in data]

@app.route('/prediksi/proses', methods=['GET', 'POST'])
@role_required(['admin'])
def prediksi_proses():
    if request.method == 'POST':
        kode_prodi = request.form.get("kode_prodi")  # Ambil kode prodi dari form
    else:
        kode_prodi = None

    conn = getConnectionDB()
    cursor = conn.cursor()

    # **Ambil Nama Program Studi berdasarkan kode_prodi**
    cursor.execute("SELECT nama_prodi FROM t_data WHERE kode_prodi = ? LIMIT 1", (kode_prodi,))
    nama_prodi_row = cursor.fetchone()
    nama_prodi = nama_prodi_row[0] if nama_prodi_row else "Program Studi Tidak Ditemukan"

    # **Ambil Hyperparameter yang Aktif dari t_hyperplane**
    cursor.execute("SELECT * FROM t_hyperplane WHERE status = 'A' LIMIT 1")
    row = cursor.fetchone()

    if not row:
        flash("Tidak ada Hyperplane yang Aktif! Silakan atur Hyperplane di menu.", "danger")
        return redirect(url_for('hyperplane'))

    # **Konversi hasil query ke dictionary**
    columns = [col[0] for col in cursor.description]
    hyperplane = dict(zip(columns, row))

    # **Ambil Data Teknik Informatika**
    cursor.execute("""
        SELECT tahun, variabel FROM t_data 
        WHERE kode_prodi = ? 
        ORDER BY tahun
    """, (kode_prodi,))
    data = cursor.fetchall()

    conn.close()

    # **Konversi Data ke Pandas DataFrame**
    tahun, target, daftar, daftar_ulang = [], [], [], []
    for row in data:
        tahun.append(row[0])
        variabel = json.loads(row[1])
        target.append(variabel.get("target", 0))
        daftar.append(variabel.get("daftar", 0))
        daftar_ulang.append(variabel.get("daftar_ulang", 0))

    df_asli = pd.DataFrame({"Tahun": tahun, "Target": target, "Daftar": daftar, "Daftar Ulang": daftar_ulang})

    # **Transformasi Pola Data**
    data_pola = []
    for i in range(len(df_asli) - 1):
        row = [
            df_asli["Target"].iloc[i], df_asli["Daftar"].iloc[i], df_asli["Daftar Ulang"].iloc[i],
            df_asli["Target"].iloc[i+1], df_asli["Daftar"].iloc[i+1], df_asli["Daftar Ulang"].iloc[i+1]
        ]
        data_pola.append(row)

    df_pola = pd.DataFrame(data_pola, columns=["X1", "X2", "X3", "X4", "X5", "Y"])

    # **Normalisasi Data Berdasarkan Hyperparameter**
    if hyperplane["normalization_method"] == "MinMax":
        scaler = MinMaxScaler(feature_range=(0.1, 0.9))
    else:
        scaler = StandardScaler()

    df_normalisasi = pd.DataFrame(scaler.fit_transform(df_pola), columns=df_pola.columns)

    # **Pisahkan Data untuk Training & Testing**
    X = df_normalisasi.iloc[:, :-1]
    y = df_normalisasi.iloc[:, -1]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # **Bangun Model ANN Berdasarkan Hyperparameter**
    model = Sequential()
    model.add(Dense(hyperplane["neurons_per_layer"], input_dim=5, activation=hyperplane["activation_function"]))

    for _ in range(hyperplane["hidden_layers"] - 1):
        model.add(Dense(hyperplane["neurons_per_layer"], activation=hyperplane["activation_function"]))

    model.add(Dense(1, activation='sigmoid'))
    
    # **Kompilasi Model**
    optimizer_dict = {
        "adam": Adam(learning_rate=hyperplane["learning_rate"]),
        "sgd": SGD(learning_rate=hyperplane["learning_rate"]),
        "rmsprop": RMSprop(learning_rate=hyperplane["learning_rate"])
    }
    optimizer = optimizer_dict.get(hyperplane["optimizer"].lower(), Adam(learning_rate=hyperplane["learning_rate"]))

    model.compile(optimizer=optimizer, loss=hyperplane["loss_function"], metrics=['mse'])

    # **Latih Model**
    history = model.fit(X_train, y_train, epochs=hyperplane["epochs"], batch_size=hyperplane["batch_size"], verbose=1, validation_data=(X_test, y_test))

    log_pelatihan = [{"epoch": i+1, "loss": history.history['loss'][i], "mse": history.history['mse'][i], 
                      "val_loss": history.history['val_loss'][i], "val_mse": history.history['val_mse'][i]}
                     for i in range(hyperplane["epochs"])]

    # **Ambil Hasil MSE Training & Testing dari Epoch Terakhir**
    mse_training = history.history['mse'][-1]  
    mse_testing = history.history['val_mse'][-1]  

    # **Prediksi Data Uji untuk Evaluasi**
    y_pred = model.predict(X_test)
    y_pred_class = [1 if val >= 0.5 else 0 for val in y_pred]
    y_test_class = [1 if val >= 0.5 else 0 for val in y_test]

    conf_matrix = confusion_matrix(y_test_class, y_pred_class)
    class_report = classification_report(y_test_class, y_pred_class, output_dict=True, zero_division=1)

    # **Visualisasi Konvergensi Model**
    epochs = list(range(1, hyperplane["epochs"] + 1))
    train_loss = [row["mse"] for row in log_pelatihan]
    val_loss = [row["val_mse"] for row in log_pelatihan]

    plt.figure(figsize=(8, 5))
    sns.lineplot(x=epochs, y=train_loss, label="Training MSE", marker="o", linestyle="-", color="blue")
    sns.lineplot(x=epochs, y=val_loss, label="Validation MSE", marker="s", linestyle="--", color="red")

    plt.xlabel("Epoch")
    plt.ylabel("Mean Squared Error (MSE)")
    plt.title("Konvergensi Model ANN - Training vs Validation MSE")
    plt.legend()
    plt.grid(True)
    plt.savefig("app/static/images/training_convergence.png")
    plt.close()

    # **Simpan Visualisasi Confusion Matrix**
    plt.figure(figsize=(6, 4))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=["Tidak Daftar Ulang", "Daftar Ulang"],
                yticklabels=["Tidak Daftar Ulang", "Daftar Ulang"])
    plt.xlabel("Prediksi")
    plt.ylabel("Aktual")
    plt.title("Confusion Matrix - Teknik Informatika")
    plt.savefig("app/static/images/confusion_matrix_ti.png")
    plt.close()

    def prediksi_tahun_berikutnya():
        tahun_terbaru = df_asli["Tahun"].iloc[-1]
        data_terbaru = df_pola.iloc[-1].values.reshape(1, -1)

        # **Normalisasi Input**
        data_terbaru_normalized = scaler.transform(data_terbaru)[:, :-1]

        # **Ambil Bobot dan Bias dari Model**
        bobot_hidden = model.layers[0].get_weights()[0]  # Bobot ke hidden layer pertama
        bias_hidden = model.layers[0].get_weights()[1]   # Bias hidden layer pertama
        bobot_output = model.layers[-1].get_weights()[0] # Bobot dari hidden layer terakhir ke output
        bias_output = model.layers[-1].get_weights()[1]  # Bias output

        # **Langkah 1: Forward Pass ke Hidden Layer**
        z_hidden = np.dot(data_terbaru_normalized, bobot_hidden) + bias_hidden
        h_hidden = 1 / (1 + np.exp(-z_hidden))  # Sigmoid Activation

        # **Langkah 2: Forward Pass ke Hidden Layer Selanjutnya (jika ada)**
        for layer in model.layers[1:-1]:  # Lewati input & output layer
            bobot = layer.get_weights()[0]
            bias = layer.get_weights()[1]
            z_hidden = np.dot(h_hidden, bobot) + bias
            h_hidden = 1 / (1 + np.exp(-z_hidden))  # Aktivasi sigmoid

        # **Langkah 3: Forward Pass ke Output Layer**
        z_output = np.dot(h_hidden, bobot_output) + bias_output
        y_pred = 1 / (1 + np.exp(-z_output))  # Sigmoid Activation

        # **Denormalisasi hasil prediksi**
        y_pred_denormalized = scaler.inverse_transform(np.concatenate((data_terbaru_normalized, y_pred), axis=1))[:, -1]

        # **Simpan Langkah-Langkah Perhitungan**
        perhitungan_rinci = {
            "tahun_prediksi": tahun_terbaru + 1,
            "prediksi_jumlah_pendaftar": round(float(y_pred_denormalized[0]), 2),
            "langkah_forward_hidden": [
                {
                    "neuron": i + 1,
                    "rumus": f"z_hidden_{i+1} = Σ(X * W) + bias",
                    "angka": f"z_hidden_{i+1} = {round(float(z_hidden[0][i]), 4)}",
                    "aktivasi": f"h_hidden_{i+1} = 1 / (1 + e^(-{round(float(z_hidden[0][i]), 4)})) = {round(float(h_hidden[0][i]), 4)}"
                } for i in range(len(z_hidden[0]))
            ],
            "langkah_forward_output": {
                "rumus": "z_output = Σ(h_hidden * W_hidden_to_output) + bias",
                "angka": f"z_output = {round(float(z_output[0]), 4)}",
                "aktivasi": f"y_pred = 1 / (1 + e^(-{round(float(z_output[0]), 4)})) = {round(float(y_pred[0]), 4)}"
            }
        }

        return perhitungan_rinci

    hasil_prediksi = prediksi_tahun_berikutnya()

    return render_template('prediksi_proses.html', 
                           data_asli=df_asli.to_dict(orient="records"), 
                           data_pola=df_pola.to_dict(orient="records"),
                           data_normalisasi=df_normalisasi.to_dict(orient="records"),
                           log_pelatihan=log_pelatihan,
                           mse_training=mse_training,  
                           mse_testing=mse_testing,  
                           hasil_prediksi=hasil_prediksi,
                           conf_matrix=conf_matrix.tolist(),
                           class_report=class_report,
                           confusion_matrix_image="images/confusion_matrix_ti.png",
                           training_convergence_image="images/training_convergence.png",
                           hyperplane=hyperplane,
                           nama_prodi=nama_prodi
                           )

@app.route('/prediksi', methods=['GET', 'POST'])
@role_required(['admin'])
def prediksi():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data khusus Teknik Informatika (kode_prodi = 55201), urutkan berdasarkan tahun
    cursor.execute("""
        SELECT DISTINCT kode_prodi, nama_prodi FROM t_data ORDER BY nama_prodi
    """)
    rows = cursor.fetchall()

    # Ambil nama kolom dari cursor.description
    columns = [col[0] for col in cursor.description]
    
    # Konversi hasil query ke list of dictionaries
    prodi = [dict(zip(columns, row)) for row in rows]
    
    conn.close()

    return render_template('prediksi.html', prodi=prodi)

# Pola data TI:
@app.route('/pola_data/ti')
@role_required(['admin'])
def pola_data_ti():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil data khusus Teknik Informatika (kode_prodi = 55201), urutkan berdasarkan tahun
    cursor.execute("""
        SELECT tahun, variabel FROM t_data 
        WHERE kode_prodi = '55201' 
        ORDER BY tahun
    """)
    data = cursor.fetchall()
    conn.close()

    # Konversi data ke DataFrame Pandas
    tahun = []
    target = []
    daftar = []
    daftar_ulang = []

    for row in data:
        tahun.append(row[0])  # Tahun
        variabel = json.loads(row[1])  # Konversi JSON
        target.append(variabel.get("target", 0))
        daftar.append(variabel.get("daftar", 0))
        daftar_ulang.append(variabel.get("daftar_ulang", 0))

    # Buat DataFrame asli
    df_asli = pd.DataFrame({
        "Tahun": tahun,
        "Target": target,
        "Daftar": daftar,
        "Daftar Ulang": daftar_ulang
    })

    # Proses pola data (format sesuai jurnal)
    data_jurnal = []

    for i in range(len(df_asli) - 1):  # Loop sampai len(df_asli) - 1
        row = [
            df_asli["Target"].iloc[i],   # X1 (Target t-1)
            df_asli["Daftar"].iloc[i],   # X2 (Daftar t-1)
            df_asli["Daftar Ulang"].iloc[i],  # X3 (Daftar Ulang t-1)
            df_asli["Target"].iloc[i+1],  # X4 (Target t)
            df_asli["Daftar"].iloc[i+1],  # X5 (Daftar t)
            df_asli["Daftar Ulang"].iloc[i+1]  # Y (Daftar Ulang t)
        ]
        data_jurnal.append(row)

    # Buat DataFrame hasil pola data
    columns_jurnal = ["X1 (Target t-1)", "X2 (Daftar t-1)", "X3 (Daftar Ulang t-1)",
                      "X4 (Target t)", "X5 (Daftar t)", "Y (Daftar Ulang t)"]
    df_jurnal = pd.DataFrame(data_jurnal, columns=columns_jurnal)

    # Konversi DataFrame ke list untuk dikirim ke template
    data_asli = df_asli.to_dict(orient="records")
    data_pola = df_jurnal.to_dict(orient="records")

    return render_template('pola_data_ti.html', data_asli=data_asli, data_pola=data_pola)

# Hyperplane model:
@app.route('/hyperplane')
@role_required(['admin'])  # Hanya admin yang bisa mengakses
def hyperplane():
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Ambil semua data hyperparameter dari database
    cursor.execute("SELECT * FROM t_hyperplane ORDER BY created_at DESC")
    rows = cursor.fetchall()
    
    # Ambil nama kolom dari cursor.description
    columns = [col[0] for col in cursor.description]
    
    # Konversi hasil query ke list of dictionaries
    hyperplanes = [dict(zip(columns, row)) for row in rows]
    
    conn.close()

    return render_template('hyperplane.html', hyperplanes=hyperplanes)

@app.route('/hyperplane/tambah')
@role_required(['admin'])
def tambah_hyperplane():
    """ Menampilkan form tambah data hyperplane """
    return render_template('tambah_hyperplane.html')


@app.route('/hyperplane/simpan', methods=['POST'])
@role_required(['admin'])
def simpan_hyperplane():
    """ Menyimpan data hyperplane baru ke database """
    conn = getConnectionDB()
    cursor = conn.cursor()

    hidden_layers = request.form['hidden_layers']
    neurons_per_layer = request.form['neurons_per_layer']
    activation_function = request.form['activation_function']
    optimizer = request.form['optimizer']
    learning_rate = request.form['learning_rate']
    loss_function = request.form['loss_function']
    epochs = request.form['epochs']
    batch_size = request.form['batch_size']
    normalization_method = request.form['normalization_method']
    status = request.form['status']

    created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Jika status = 'A', ubah semua data lain menjadi 'N'
    if status == "A":
        cursor.execute("UPDATE t_hyperplane SET status = 'N'")

    query = """
        INSERT INTO t_hyperplane (hidden_layers, neurons_per_layer, activation_function, optimizer, 
                                  learning_rate, loss_function, epochs, batch_size, normalization_method, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    values = (hidden_layers, neurons_per_layer, activation_function, optimizer,
              learning_rate, loss_function, epochs, batch_size, normalization_method, status, created_at)

    cursor.execute(query, values)
    conn.commit()
    conn.close()

    flash("Hyperplane berhasil ditambahkan!", "success")
    return redirect(url_for('hyperplane'))

@app.route('/hyperplane/edit/<int:id>', methods=['GET', 'POST'])
@role_required(['admin'])
def edit_hyperplane(id):
    conn = getConnectionDB()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Ambil data dari form
        hidden_layers = request.form['hidden_layers']
        neurons_per_layer = request.form['neurons_per_layer']
        activation_function = request.form['activation_function']
        optimizer = request.form['optimizer']
        learning_rate = request.form['learning_rate']
        loss_function = request.form['loss_function']
        epochs = request.form['epochs']
        batch_size = request.form['batch_size']
        normalization_method = request.form['normalization_method']
        status = request.form['status']

        # Jika status = 'A', ubah semua data lain menjadi 'N' sebelum memperbarui
        if status == "A":
            cursor.execute("UPDATE t_hyperplane SET status = 'N'")

        # Update data
        cursor.execute("""
            UPDATE t_hyperplane 
            SET hidden_layers=?, neurons_per_layer=?, activation_function=?, optimizer=?, 
                learning_rate=?, loss_function=?, epochs=?, batch_size=?, normalization_method=?, status=?
            WHERE id=?
        """, (hidden_layers, neurons_per_layer, activation_function, optimizer, 
              learning_rate, loss_function, epochs, batch_size, normalization_method, status, id))
        conn.commit()
        conn.close()

        flash("Data Hyperplane berhasil diperbarui!", "success")
        return redirect(url_for('hyperplane'))

    # **GET Request: Ambil data lama untuk ditampilkan di form edit**
    cursor.execute("SELECT * FROM t_hyperplane WHERE id = ?", (id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        columns = [col[0] for col in cursor.description]
        hyperplane = dict(zip(columns, row))
        return render_template('edit_hyperplane.html', hyperplane=hyperplane)
    else:
        flash("Data tidak ditemukan!", "danger")
        return redirect(url_for('hyperplane'))


@app.route('/hyperplane/hapus/<int:id>')
@role_required(['admin'])
def hapus_hyperplane(id):
    conn = getConnectionDB()
    cursor = conn.cursor()

    # Hapus data dari database
    cursor.execute("DELETE FROM t_hyperplane WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Data Hyperplane berhasil dihapus!", "success")
    return redirect(url_for('hyperplane'))
