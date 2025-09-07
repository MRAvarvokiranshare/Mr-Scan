#!/usr/bin/env python3
import sys, socket, time, ssl, requests
from urllib.parse import urlparse
from colorama import init, Fore, Style

# init colorama
init(autoreset=True)

# رنگ‌ها
def ok(s):    return Fore.GREEN + s + Style.RESET_ALL
def warn(s):  return Fore.YELLOW + s + Style.RESET_ALL
def bad(s):   return Fore.RED + s + Style.RESET_ALL
def info(s):  return Fore.CYAN + s + Style.RESET_ALL

# لیست سفید (سایت‌های معتبر که الکی مشکوک نشون داده نشن)
WHITELIST = ["google.com", "facebook.com", "twitter.com", "github.com"]

def check_ports(ip):
    """بررسی پورت‌های مهم روی IP"""
    ports = [80, 443, 21, 22, 25, 3306]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def check_url(url):
    result = {"ssl": None, "status": None, "ip": None, "time": None, "keywords": None, "ports": None}
    suspicious_score = 0

    try:
        # Parse URL
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        if host.startswith("www."):
            host = host[4:]

        print(info(f"\n🔍 Scanning: {url}"))

        # Whitelist
        if any(host.endswith(w) for w in WHITELIST):
            print(ok(f"✅ {host} is in whitelist (Trusted site)"))
            print(ok("───────────── RESULT ─────────────"))
            print(ok("✅ Safe"))
            return

        # Get IP
        try:
            ip = socket.gethostbyname(host)
            result["ip"] = ip
            print(info(f"🌐 IP Address: {ip}"))
        except:
            print(bad("❌ Could not resolve IP"))
            suspicious_score += 2

        # SSL check
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        issuer = dict(x[0] for x in cert['issuer'])
                        issued_by = issuer.get('organizationName', 'Unknown')
                        result["ssl"] = "valid"
                        print(ok(f"🔒 SSL: Valid certificate (Issued by {issued_by})"))
            except:
                result["ssl"] = "invalid"
                print(warn("⚠️ SSL: Invalid or expired certificate"))
                suspicious_score += 1
        else:
            print(warn("⚠️ No SSL (HTTP only)"))
            suspicious_score += 1

        # HTTP request
        start = time.time()
        r = requests.get(url, timeout=8)
        elapsed = int((time.time() - start) * 1000)
        result["time"] = elapsed
        result["status"] = r.status_code
        print(info(f"⏱ Response time: {elapsed} ms"))
        print(info(f"📡 HTTP Status: {r.status_code}"))

        if r.status_code >= 400:
            suspicious_score += 1

        # Keyword check
        keywords = ["login","password","bank","verify","account","paypal","signin","security"]
        body = r.text.lower()
        if any(k in body for k in keywords):
            result["keywords"] = True
            print(warn("⚠️ Suspicious keywords detected"))
            suspicious_score += 1
        else:
            result["keywords"] = False
            print(ok("✅ No phishing keywords found"))

        # Port scan
        if result["ip"]:
            open_ports = check_ports(result["ip"])
            result["ports"] = open_ports
            if open_ports:
                print(warn(f"⚠️ Open ports detected: {open_ports}"))
            else:
                print(ok("✅ No risky open ports detected"))

    except requests.exceptions.RequestException as e:
        print(bad(f"❌ Error: {e}"))
        suspicious_score += 2

    # Final decision
    print("\n───────────── RESULT ─────────────")
    if suspicious_score >= 2:
        print(bad("❌ Malicious"))
    elif suspicious_score == 1:
        print(warn("⚠️ Suspicious"))
    else:
        print(ok("✅ Safe"))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <URL>")
        sys.exit(1)
    check_url(sys.argv[1])
