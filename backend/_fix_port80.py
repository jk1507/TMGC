"""Fix port 80 false positive - don't flag HTTP as exposed on web servers."""
with open('main.py', 'r', encoding='utf-8') as f:
    content = f.read()

old = """    for port in open_ports:
        if port in PORT_INTEL:
            # Suppress 8080/8443 false positives for Cloudflare-hosted domains
            if port in (8080, 8443) and "CLOUDFLARE" in parsed_meta.get("hosting_space", "").upper():
                add_finding(findings, f"INFO: Port {port} open on Cloudflare edge - expected for proxy infrastructure.")
            else:
                add_finding(findings, f"EXPOSED PORT: {PORT_INTEL[port]}")
                score += 8 if port in {23, 3389, 445, 5900} else 5"""

new = """    for port in open_ports:
        if port in PORT_INTEL:
            # Standard web ports (80=HTTP, 443=HTTPS) are expected on any
            # web server. HTTP on port 80 typically redirects to HTTPS on
            # port 443. These are not risk indicators and should be INFO.
            if port in (80, 443):
                add_finding(findings, f"INFO: Port {port} ({'HTTP' if port == 80 else 'HTTPS'}) - standard web port, expected.")
            # Suppress 8080/8443 false positives for Cloudflare-hosted domains
            elif port in (8080, 8443) and "CLOUDFLARE" in parsed_meta.get("hosting_space", "").upper():
                add_finding(findings, f"INFO: Port {port} open on Cloudflare edge - expected for proxy infrastructure.")
            else:
                add_finding(findings, f"EXPOSED PORT: {PORT_INTEL[port]}")
                score += 8 if port in {23, 3389, 445, 5900} else 5"""

if old in content:
    content = content.replace(old, new, 1)
    with open('main.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Fix applied successfully!")
else:
    print("Pattern NOT found")
