import streamlit as st
from parser_module import parse_email_header
from analyzer_module import generate_findings
from scoring_module import calculate_score, get_verdict


st.set_page_config(
    page_title="Phishing Email Analyzer",
    page_icon="📧",
    layout="wide"
)


st.title("📧 Phishing Email Analyzer")
st.write(
    "Tool sederhana untuk menganalisis raw email header, "
    "mendeteksi anomali IP/domain pengirim, serta membaca status SPF, DKIM, dan DMARC."
)


sample_safe = """From: Campus IT <it@kampus.ac.id>
Return-Path: <it@kampus.ac.id>
Reply-To: it@kampus.ac.id
Received: from mail.kampus.ac.id (103.10.20.30)
Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass
Subject: Informasi Akademik
Date: Mon, 10 Jun 2026 08:00:00 +0700
Message-ID: <12345@kampus.ac.id>"""


sample_phishing = """From: Bank Support <support@bankabc.com>
Return-Path: <verify@random-mail.ru>
Reply-To: attacker@gmail.com
Received: from random-mail.ru (185.44.22.10)
Authentication-Results: mx.google.com; spf=fail dkim=fail dmarc=fail
Subject: Urgent Account Verification
Date: Mon, 10 Jun 2026 09:00:00 +0700
Message-ID: <fake123@random-mail.ru>"""


with st.sidebar:
    st.header("Sample Header")
    sample_option = st.selectbox(
        "Pilih sample:",
        ["Kosong", "Safe Email", "Phishing Email"]
    )

    if sample_option == "Safe Email":
        default_header = sample_safe
    elif sample_option == "Phishing Email":
        default_header = sample_phishing
    else:
        default_header = ""

    st.info("Paste raw email header pada kolom utama, lalu klik Analyze.")


raw_header = st.text_area(
    "Paste Raw Email Header:",
    value=default_header,
    height=300
)


analyze_button = st.button("Analyze Header")


if analyze_button:
    if not raw_header.strip():
        st.warning("Masukkan raw email header terlebih dahulu.")
    else:
        parsed_data = parse_email_header(raw_header)
        findings = generate_findings(parsed_data)
        score = calculate_score(findings)
        verdict = get_verdict(score)

        st.subheader("1. Header Information")

        col1, col2 = st.columns(2)

        with col1:
            st.write("**From:**", parsed_data["from"])
            st.write("**From Email:**", parsed_data["from_email"])
            st.write("**From Domain:**", parsed_data["from_domain"])
            st.write("**Return-Path:**", parsed_data["return_path"])
            st.write("**Return-Path Domain:**", parsed_data["return_path_domain"])

        with col2:
            st.write("**Reply-To:**", parsed_data["reply_to"])
            st.write("**Reply-To Domain:**", parsed_data["reply_to_domain"])
            st.write("**Subject:**", parsed_data["subject"])
            st.write("**Date:**", parsed_data["date"])
            st.write("**Message-ID:**", parsed_data["message_id"])

        st.subheader("2. Sender IP Analysis")
        st.write("**Sender IP:**", parsed_data["sender_ip"])
        st.write("**All Detected IPs:**", parsed_data["ips"])

        st.subheader("3. Authentication Results")

        auth_col1, auth_col2, auth_col3 = st.columns(3)

        with auth_col1:
            st.metric("SPF", parsed_data["spf"].upper())

        with auth_col2:
            st.metric("DKIM", parsed_data["dkim"].upper())

        with auth_col3:
            st.metric("DMARC", parsed_data["dmarc"].upper())

        st.subheader("4. Risk Analysis")

        st.progress(score / 100)
        st.write(f"**Risk Score:** {score}/100")

        if verdict == "Aman":
            st.success(f"Verdict: {verdict}")
        elif verdict == "Mencurigakan":
            st.warning(f"Verdict: {verdict}")
        else:
            st.error(f"Verdict: {verdict}")

        st.subheader("5. Findings")

        if findings:
            for finding in findings:
                if finding["type"] == "public_ip":
                    st.info(f"- {finding['message']}")
                else:
                    st.warning(f"- {finding['message']}")
        else:
            st.success("Tidak ditemukan indikasi mencurigakan pada header.")