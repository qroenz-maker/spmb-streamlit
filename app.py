import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import os
import time
from datetime import datetime

# =========================
# KONFIGURASI
# =========================
DB = "database.db"
LOCK_DIR = "locks"

os.makedirs(LOCK_DIR, exist_ok=True)

# =========================
# DATABASE
# =========================
conn = sqlite3.connect(DB, check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT,
    npsn TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS spmb (
    nik TEXT UNIQUE,
    nama TEXT,
    npsn_asal TEXT,
    npsn_tujuan TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS conflicts (
    waktu TEXT,
    npsn_operator TEXT,
    row_no INTEGER,
    kolom TEXT,
    nilai TEXT,
    alasan TEXT
)
""")

conn.commit()

# =========================
# USER DEFAULT
# =========================
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

c.execute("INSERT OR IGNORE INTO users VALUES (?,?,?,?)",
          ("dinas", hash_pw("dinas123"), "DINAS", None))
c.execute("INSERT OR IGNORE INTO users VALUES (?,?,?,?)",
          ("operator1", hash_pw("operator123"), "OPERATOR", "12345678"))
conn.commit()

# =========================
# AUTH
# =========================
def login(username, password):
    c.execute("SELECT role, npsn, password FROM users WHERE username=?", (username,))
    r = c.fetchone()
    if r and r[2] == hash_pw(password):
        return r[0], r[1]
    return None, None

# =========================
# LOCK (ANTRIAN UPLOAD)
# =========================
def acquire_lock(npsn):
    lockfile = f"{LOCK_DIR}/{npsn}.lock"
    if os.path.exists(lockfile):
        return False
    open(lockfile, "w").close()
    return True

def release_lock(npsn):
    lockfile = f"{LOCK_DIR}/{npsn}.lock"
    if os.path.exists(lockfile):
        os.remove(lockfile)

# =========================
# VALIDASI & PROSES
# =========================
def process_excel(df, npsn_operator):
    sukses = 0
    konflik = []

    for i, row in df.iterrows():
        row_no = i + 2

        nik = str(row["NIK"]).strip()
        nama = str(row["NAMA"]).strip()
        npsn_asal = str(row["NPSN_ASAL"]).strip()
        npsn_tujuan = str(row["NPSN_TUJUAN"]).strip()

        if len(nik) != 16 or not nik.isdigit():
            konflik.append((row_no, "NIK", nik, "NIK harus 16 digit"))
            continue

        if npsn_tujuan != npsn_operator:
            konflik.append((row_no, "NPSN_TUJUAN", npsn_tujuan, "Tidak sesuai akun operator"))
            continue

        try:
            c.execute(
                "INSERT INTO spmb VALUES (?,?,?,?)",
                (nik, nama, npsn_asal, npsn_tujuan)
            )
            sukses += 1
        except sqlite3.IntegrityError:
            konflik.append((row_no, "NIK", nik, "NIK duplikat nasional"))

    conn.commit()

    for k in konflik:
        c.execute(
            "INSERT INTO conflicts VALUES (?,?,?,?,?,?)",
            (datetime.now(), npsn_operator, *k)
        )
    conn.commit()

    return sukses, konflik

# =========================
# UI
# =========================
st.title("📊 Sistem Upload SPMB Terpusat")

if "login" not in st.session_state:
    st.session_state.login = False

if not st.session_state.login:
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Login"):
        role, npsn = login(u, p)
        if role:
            st.session_state.login = True
            st.session_state.role = role
            st.session_state.npsn = npsn
            st.success("Login berhasil")
            st.rerun()
        else:
            st.error("Login gagal")
    st.stop()

# =========================
# OPERATOR
# =========================
if st.session_state.role == "OPERATOR":
    st.subheader(f"🏫 Operator Sekolah (NPSN {st.session_state.npsn})")

    file = st.file_uploader("Upload Excel SPMB", type=["xlsx"])

    if file:
        if not acquire_lock(st.session_state.npsn):
            st.warning("⏳ Upload sedang diproses, menunggu antrian...")
            st.stop()

        try:
            df = pd.read_excel(file, sheet_name="hasil_spmb")
        except:
            st.error("❌ Sheet harus bernama: hasil_spmb")
            release_lock(st.session_state.npsn)
            st.stop()

        wajib = ["NIK", "NAMA", "NPSN_ASAL", "NPSN_TUJUAN"]
        if list(df.columns) != wajib:
            st.error("❌ Header tidak sesuai template")
            release_lock(st.session_state.npsn)
            st.stop()

        with st.spinner("Memproses & validasi data..."):
            sukses, konflik = process_excel(df, st.session_state.npsn)
            time.sleep(1)

        release_lock(st.session_state.npsn)

        st.success(f"✅ Data masuk: {sukses}")
        st.error(f"❌ Konflik: {len(konflik)}")

        if konflik:
            st.dataframe(pd.DataFrame(
                konflik,
                columns=["Baris", "Kolom", "Nilai", "Alasan"]
            ))

    st.markdown("### ⬇ Download Data Sekolah")
    df = pd.read_sql(
        "SELECT * FROM spmb WHERE npsn_tujuan=?",
        conn,
        params=(st.session_state.npsn,)
    )
    st.download_button(
        "Download CSV",
        df.to_csv(index=False),
        "spmb_sekolah.csv"
    )

# =========================
# DINAS
# =========================
if st.session_state.role == "DINAS":
    st.subheader("🏛 Super Admin (Dinas)")

    st.markdown("### 📊 Rekap Nasional")
    df = pd.read_sql("SELECT * FROM spmb", conn)
    st.dataframe(df)
    st.download_button(
        "Download Rekap Nasional",
        df.to_csv(index=False),
        "rekap_spmb_nasional.csv"
    )

    st.markdown("### ⚠ Konflik Data")
    dfk = pd.read_sql("SELECT * FROM conflicts", conn)
    st.dataframe(dfk)
