SCORE_RULES = {
    "spf_fail": 25,
    "spf_weak": 10,
    "spf_none": 10,
    "dkim_fail": 25,
    "dkim_none": 10,
    "dmarc_fail": 30,
    "dmarc_none": 15,
    "return_path_mismatch": 10,
    "reply_to_mismatch": 10,
    "reply_to_free_domain": 10,
    "ip_not_found": 5,
    "private_ip": 5,
    "invalid_ip": 5,
    "public_ip": 0
}


def calculate_score(findings):
    score = 0

    for finding in findings:
        finding_type = finding.get("type")
        score += SCORE_RULES.get(finding_type, 0)

    if score > 100:
        score = 100

    return score


def get_verdict(score):
    if score <= 30:
        return "Aman"
    elif score <= 60:
        return "Mencurigakan"
    else:
        return "Berpotensi Phishing"