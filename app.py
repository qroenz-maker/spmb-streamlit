import streamlit as st
import pandas as pd
import hashlib
import os
from supabase import create_client

# =========================
# CONFIG
# =========================
st.set_page_config(page_title="SPMB Terpusat", layout="wide")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("Supabase credentials belum diset di Streamlit Secrets.")
    st.stop()

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# =========================
# HASH
# =========================
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# =========================
# LOGIN FUNCTION
# =========================
def login(username, password):
    hpw = hash_pw(password)
    res = supabase.table("users") \
        .select("*") \
        .eq("username", username) \
        .eq("password", hpw) \
        .execute()

    if not res.data:
        return None
    return res.data[0]

# =========================
# SESSION INIT
# =========================
if "login" not in st.session_state:
    st.session_state.login = False
    st.session_state.user = None

# =========================
# LOGIN PAGE
# =========================
if not st.session_state.login:

    st.title("🔐 Login SPMB Terpusat")

    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        user = login(u, p)

        if not user:
            st.error("Username atau password salah")
            st.stop()

        st.session_state.login = True
        st.session_state.user = user
        st.rerun()

    st.stop()

# =========================
# LOGOUT
# =========================
col1, col2 = st.columns([8,2])
with col2:
    if st.button("Logout"):
        st.session_state.clear()
        st.rerun()

role = st.session_state.user["role"]

# =========================
# DASHBOARD OPERATOR
# =========================
if role == "OPERATOR":

    npsn = st.session_state.user["npsn"]

    sekolah = supabase.table("schools") \
        .select("*") \
        .eq("npsn", npsn) \
        .execute().data[0]

    st.title("🏫 Dashboard Sekolah")
    st.subheader(sekolah["nama_sekolah"])

    data = supabase.table("spmb") \
        .select("*") \
        .eq("npsn_tujuan", npsn) \
        .execute().data

    df = pd.DataFrame(data)

    st.metric("Total Siswa", len(df))
    st.dataframe(df)

    st.markdown("### Upload Excel")

    file = st.file_uploader("Upload File Excel", type=["xlsx"])

    if file:
        df_upload = pd.read_excel(file)

        for _, row in df_upload.iterrows():

            if len(str(row["NIK"])) != 16:
                continue

            supabase.table("spmb").upsert({
                "nik": str(row["NIK"]),
                "nama": row["NAMA"],
                "npsn_asal": row["NPSN_ASAL"],
                "npsn_tujuan": npsn
            }).execute()

        st.success("Upload berhasil")
        st.rerun()

# =========================
# DASHBOARD DINAS
# =========================
if role == "DINAS":

    st.title("🏛 Dashboard Dinas")

    # REKAP
    data = supabase.rpc("rekap_sekolah").execute().data
    df = pd.DataFrame(data)

    if not df.empty:

        filter_sekolah = st.selectbox(
            "Filter Sekolah",
            ["Semua"] + df["nama_sekolah"].tolist()
        )

        if filter_sekolah != "Semua":
            df = df[df["nama_sekolah"] == filter_sekolah]

        st.dataframe(df)

        st.bar_chart(
            df.set_index("nama_sekolah")["total_siswa"]
        )

    # DETAIL
    st.markdown("### Detail Nasional")
    all_data = supabase.table("spmb").select("*").execute().data
    st.dataframe(pd.DataFrame(all_data))

    # =========================
    # MANAJEMEN USER
    # =========================
    st.markdown("### 👥 Manajemen User")

    users = supabase.table("users").select("username,role,npsn").execute().data
    st.dataframe(pd.DataFrame(users))

    with st.form("add_user"):
        u = st.text_input("Username")
        p = st.text_input("Password")
        role_new = st.selectbox("Role", ["OPERATOR","DINAS"])
        npsn_new = st.text_input("NPSN (isi jika OPERATOR)")
        submit = st.form_submit_button("Tambah User")

        if submit:
            supabase.table("users").insert({
                "username": u,
                "password": hash_pw(p),
                "role": role_new,
                "npsn": npsn_new if role_new=="OPERATOR" else None
            }).execute()

            st.success("User berhasil ditambahkan")
            st.rerun()
