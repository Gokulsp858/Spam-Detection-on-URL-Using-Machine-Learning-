# ai_domain.py
import whois
import socket
import ssl
import dns.resolver
import datetime
import re

def safe_get_whois(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception:
        return None

def get_domain_from_url(url):
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.hostname or ''

def domain_age_days(domain):
    w = safe_get_whois(domain)
    try:
        if w and w.creation_date:
            cd = w.creation_date
            # handle list or single date
            if isinstance(cd, list):
                cd = cd[0]
            if isinstance(cd, str):
                cd = datetime.datetime.strptime(cd, '%Y-%m-%d')
            delta = datetime.datetime.utcnow() - cd
            return max(0, delta.days)
    except Exception:
        pass
    return None

def ssl_days_left(domain, timeout=4):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                notAfter = cert.get('notAfter')
                if notAfter:
                    exp = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
                    diff = exp - datetime.datetime.utcnow()
                    return diff.days
    except Exception:
        return None

def resolve_ttl(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=3)
        if answers.rrset and answers.rrset.ttl:
            return int(answers.rrset.ttl)
    except Exception:
        return None
    return None

def domain_intel(url):
    domain = get_domain_from_url(url)
    if not domain:
        return {"domain_score": 0.5, "reason": "no-domain"}

    info = {}
    age = domain_age_days(domain)
    ssl_days = ssl_days_left(domain)
    ttl = resolve_ttl(domain)

    # heuristics -> normalized scores
    score = 0.5
    reasons = []

    # domain age
    if age is None:
        score += 0.05
        reasons.append("no-whois")
    else:
        if age < 30:
            score += 0.35; reasons.append("young-domain")
        elif age < 365:
            score += 0.15; reasons.append("recent-domain")
        else:
            score -= 0.15; reasons.append("old-domain")

    if ssl_days is None:
        score += 0.2; reasons.append("no-ssl")
    else:
        if ssl_days < 30:
            score += 0.25; reasons.append("ssl-expiring")
        else:
            score -= 0.1; reasons.append("ssl-good")

    if ttl is not None and ttl < 300:
        score += 0.1; reasons.append("low-ttl")

    # clamp to 0..1
    score = max(0.0, min(1.0, score))
    return {"domain_score": score, "domain_age_days": age, "ssl_days_left": ssl_days, "ttl": ttl, "reasons": reasons}
