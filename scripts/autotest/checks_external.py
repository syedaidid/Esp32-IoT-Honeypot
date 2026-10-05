# External/network checks — run from ANY machine with internet access.
# Verifies TLS, HTTP->HTTPS redirect and real public reachability of the site.
# Invoke:  python3 scripts/autotest/run_matrix.py --mode external
import harness as H

TARGET = "https://fyp.syedaidid.xyz"


def s11():
    """http:// must redirect to https, and the certificate must be valid."""
    code, hdrs = H.http_nofollow("http://fyp.syedaidid.xyz/")
    loc = hdrs.get("Location", hdrs.get("location", ""))
    redirected = code in (301, 302, 307, 308) and loc.startswith("https://")
    try:
        info = H.tls_info()
        cert_ok = True
        cert_txt = f"issuer={info['issuer'].get('organizationName', '?')}, " \
                   f"valid until {info['not_after']}"
    except Exception as e:
        cert_ok, cert_txt = False, f"TLS error: {e}"
    return (redirected and cert_ok,
            f"http -> {code} Location={loc or '(none)'}; cert {cert_txt}")


def r09():
    """Site stays reachable; certificate valid."""
    ok_count = 0
    for _ in range(3):
        code, _, _ = H.http(f"{TARGET}/accounts/login/", timeout=10)
        if code == 200:
            ok_count += 1
        import time as _t; _t.sleep(0.5)
    try:
        H.tls_info(); cert_ok = True
    except Exception:
        cert_ok = False
    return (ok_count == 3 and cert_ok,
            f"{ok_count}/3 probes returned 200; cert valid={cert_ok}")


def i09():
    """Console loads over HTTPS through host nginx + Let's Encrypt."""
    code, body, dt = H.http(f"{TARGET}/accounts/login/", timeout=10)
    login_ok = code == 200 and (b"password" in body.lower())
    root, hdrs = H.http_nofollow(f"{TARGET}/")
    loc = hdrs.get("Location", "")
    root_ok = root in (301, 302) and "/accounts/login/" in loc
    return (login_ok and root_ok,
            f"login page {code} (form={login_ok}, {dt:.2f}s); unauth / -> {root} {loc}")


def p01_ext():
    code, _, dt = H.http(f"{TARGET}/accounts/login/", timeout=10)
    return code == 200 and dt < 5, f"public entry page {code} in {dt:.2f}s (limit 5s)"


CHECKS = {"NFT-S11": s11, "NFT-R09": r09, "FT-I09": i09, "NFT-P01e": p01_ext}