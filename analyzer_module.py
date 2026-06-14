import ipaddress


FREE_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "aol.com",
    "protonmail.com"
]


def is_free_email_domain(domain):
    return domain in FREE_EMAIL_DOMAINS


def analyze_ip(parsed_data):
    findings = []
    sender_ip = parsed_data.get("sender_ip", "-")

    if sender_ip == "-":
        findings.append({
            "type": "ip_not_found",
            "message": "IP pengirim tidak ditemukan pada header."
        })
        return findings

    try:
        ip_obj = ipaddress.ip_address(sender_ip)

        if ip_obj.is_private:
            findings.append({
                "type": "private_ip",
                "message": "IP pengirim merupakan private IP, sehingga perlu diperiksa lebih lanjut."
            })
        else:
            findings.append({
                "type": "public_ip",
                "message": "IP pengirim merupakan public IP."
            })

    except ValueError:
        findings.append({
            "type": "invalid_ip",
            "message": "Format IP pengirim tidak valid."
        })

    return findings


def analyze_domain_mismatch(parsed_data):
    findings = []

    from_domain = parsed_data.get("from_domain", "-")
    return_path_domain = parsed_data.get("return_path_domain", "-")
    reply_to_domain = parsed_data.get("reply_to_domain", "-")

    if from_domain != "-" and return_path_domain != "-":
        if from_domain != return_path_domain:
            findings.append({
                "type": "return_path_mismatch",
                "message": "Domain Return-Path berbeda dengan domain From."
            })

    if from_domain != "-" and reply_to_domain != "-":
        if from_domain != reply_to_domain:
            findings.append({
                "type": "reply_to_mismatch",
                "message": "Domain Reply-To berbeda dengan domain From."
            })

    if reply_to_domain != "-" and is_free_email_domain(reply_to_domain):
        if from_domain != reply_to_domain:
            findings.append({
                "type": "reply_to_free_domain",
                "message": "Reply-To menggunakan domain email gratis yang berbeda dari domain pengirim."
            })

    return findings


def analyze_authentication(parsed_data):
    findings = []

    spf = parsed_data.get("spf", "none")
    dkim = parsed_data.get("dkim", "none")
    dmarc = parsed_data.get("dmarc", "none")

    if spf == "fail":
        findings.append({
            "type": "spf_fail",
            "message": "SPF gagal. IP pengirim tidak diizinkan mengirim email untuk domain tersebut."
        })
    elif spf in ["softfail", "neutral"]:
        findings.append({
            "type": "spf_weak",
            "message": "SPF tidak memberikan hasil kuat atau hanya softfail."
        })
    elif spf == "none":
        findings.append({
            "type": "spf_none",
            "message": "Status SPF tidak ditemukan."
        })

    if dkim == "fail":
        findings.append({
            "type": "dkim_fail",
            "message": "DKIM gagal. Tanda tangan email tidak valid."
        })
    elif dkim == "none":
        findings.append({
            "type": "dkim_none",
            "message": "Status DKIM tidak ditemukan."
        })

    if dmarc == "fail":
        findings.append({
            "type": "dmarc_fail",
            "message": "DMARC gagal. Domain pengirim tidak lolos validasi kebijakan DMARC."
        })
    elif dmarc == "none":
        findings.append({
            "type": "dmarc_none",
            "message": "Status DMARC tidak ditemukan."
        })

    return findings


def generate_findings(parsed_data):
    findings = []

    findings.extend(analyze_authentication(parsed_data))
    findings.extend(analyze_domain_mismatch(parsed_data))
    findings.extend(analyze_ip(parsed_data))

    return findings