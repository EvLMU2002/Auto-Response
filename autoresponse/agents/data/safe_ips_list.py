SAFE_IPS = [
    "1.1.1.1",           # Cloudflare
    "1.0.0.1",           # Cloudflare (secondary)
    "8.8.8.8",           # Google
    "8.8.4.4",           # Google (secondary)
    "9.9.9.9",           # Quad9
    "149.112.112.112",   # Quad9 (secondary)
    "208.67.222.222",    # OpenDNS
    "208.67.220.220",    # OpenDNS (secondary)
    "1.1.1.2",           # Cloudflare (malware blocking)
    "1.0.0.2",           # Cloudflare (malware blocking secondary)
    "9.9.9.10",          # Quad9 (unfiltered)
    "149.112.112.10",    # Quad9 (unfiltered secondary)
    "208.67.222.220",    # OpenDNS (tertiary)
    "208.67.220.222",    # OpenDNS (quaternary)
    "1.1.1.3"            # Cloudflare (malware + adult content blocking)
]