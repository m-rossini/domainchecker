#!/usr/bin/env python3
"""
Simple domain availability checker for .com (US), .co.uk (UK), .com.br (Brazil)
Input file: one base domain per line (e.g., "example")
Output: CSV with status for each TLD
"""

import socket
import csv
import logging

# WHOIS servers
WHOIS = {
    'com': ('whois.verisign-grs.com', 43),
    'co.uk': ('whois.nic.uk', 43),
    'com.br': ('whois.registro.br', 43)
}

TIMEOUT = 10

ERROR_PATTERNS = (
    'quota',
    'limit exceeded',
    'query rate',
    'temporarily unavailable',
    'connection limit',
    'try again later',
    'timeout',
)

ERROR_PATTERNS_BY_TLD = {
    # Verisign/.com specific throttling and abuse-control messages.
    'com': (
        'whois limit exceeded',
        'exceeded your query quota',
        'exceeded allowable query limits',
        'exceeded the maximum allowable number of whois queries',
    ),
    'co.uk': (),
    'com.br': (),
}

AVAILABLE_PATTERNS = {
    'com': ('no match', 'not found'),
    'co.uk': ('no match', 'not found'),
    'com.br': ('no match', 'not found', 'disponivel', 'dispon\xedvel', 'available'),
}

def check_whois(domain, tld):
    """Return 'available' or 'not available' for domain.tld"""
    server, port = WHOIS[tld]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((server, port))
            sock.send(f"{domain}.{tld}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

        if not response:
            # Empty body from provider is not a valid availability signal.
            return 'error'

        text = response.decode('utf-8', errors='ignore').lower()

        # WHOIS providers may rate-limit and return error text with HTTP-like success.
        if any(pattern in text for pattern in ERROR_PATTERNS):
            return 'error'

        if any(pattern in text for pattern in ERROR_PATTERNS_BY_TLD[tld]):
            return 'error'

        if any(pattern in text for pattern in AVAILABLE_PATTERNS[tld]):
            return 'available'

        return 'not available'
    except Exception:
        return 'error'

def main():
    input_file = 'domains.txt'
    output_file = 'results.csv'

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Read base domains
    try:
        with open(input_file, 'r') as f:
            bases = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error('%s not found', input_file)
        return []

    logging.info('Checking %d domains...', len(bases))
    results = []
    # Availability bitmask mapping: BR=1, US=2, UK=4
    # CSV columns will be ordered as: domain, availability_code, br, us, uk
    for base in bases:
        logging.info('Checking %s...', base)
        us = check_whois(base, 'com')
        uk = check_whois(base, 'co.uk')
        br = check_whois(base, 'com.br')
        avail_mask = 0
        if br == 'available':
            avail_mask |= 1
        if us == 'available':
            avail_mask |= 2
        if uk == 'available':
            avail_mask |= 4
        results.append([base, avail_mask, br, us, uk])

    # Write CSV
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['domain', 'availability_code', 'br', 'us', 'uk'])
            writer.writerows(results)
        logging.info('Done. Results saved to %s', output_file)
    except Exception as e:
        logging.error('Failed to write results to %s: %s', output_file, e)

    logging.info('Summary:')
    for row in results:
        # row format: [domain, availability_code, br, us, uk]
        logging.info('%s: availability_code=%d, BR=%s, US=%s, UK=%s', row[0], row[1], row[2], row[3], row[4])

    return results


if __name__ == '__main__':
    main()