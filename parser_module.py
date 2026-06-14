import re
from email.parser import Parser


def extract_header_value(headers, field_name):
    value = headers.get(field_name)
    if value:
        return value.strip()
    return "-"


def extract_email_address(text):
    if not text or text == "-":
        return "-"

    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    if match:
        return match.group(0).lower()

    return "-"


def extract_domain(email_address):
    if not email_address or email_address == "-":
        return "-"

    if "@" in email_address:
        return email_address.split("@")[-1].lower()

    return "-"


def extract_ips(raw_header):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, raw_header)

    valid_ips = []
    for ip in ips:
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            valid_ips.append(ip)

    return valid_ips


def extract_auth_status(raw_header, auth_type):
    pattern = rf'{auth_type}\s*=\s*([a-zA-Z]+)'
    match = re.search(pattern, raw_header, re.IGNORECASE)

    if match:
        return match.group(1).lower()

    return "none"


def parse_email_header(raw_header):
    headers = Parser().parsestr(raw_header)

    from_value = extract_header_value(headers, "From")
    return_path_value = extract_header_value(headers, "Return-Path")
    reply_to_value = extract_header_value(headers, "Reply-To")
    subject_value = extract_header_value(headers, "Subject")
    date_value = extract_header_value(headers, "Date")
    message_id_value = extract_header_value(headers, "Message-ID")

    from_email = extract_email_address(from_value)
    return_path_email = extract_email_address(return_path_value)
    reply_to_email = extract_email_address(reply_to_value)

    from_domain = extract_domain(from_email)
    return_path_domain = extract_domain(return_path_email)
    reply_to_domain = extract_domain(reply_to_email)

    ips = extract_ips(raw_header)
    sender_ip = ips[0] if ips else "-"

    spf_status = extract_auth_status(raw_header, "spf")
    dkim_status = extract_auth_status(raw_header, "dkim")
    dmarc_status = extract_auth_status(raw_header, "dmarc")

    parsed_data = {
        "from": from_value,
        "from_email": from_email,
        "from_domain": from_domain,
        "return_path": return_path_value,
        "return_path_email": return_path_email,
        "return_path_domain": return_path_domain,
        "reply_to": reply_to_value,
        "reply_to_email": reply_to_email,
        "reply_to_domain": reply_to_domain,
        "subject": subject_value,
        "date": date_value,
        "message_id": message_id_value,
        "ips": ips,
        "sender_ip": sender_ip,
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status
    }

    return parsed_data