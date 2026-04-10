#!/usr/bin/env python3
"""
Simple domain availability checker for .com (US), .co.uk (UK), .com.br (Brazil)
Input file: one base domain per line (e.g., "example")
Output: CSV with status for each TLD
"""

import argparse
import csv
import logging
import os
import socket
import sys
import time
from datetime import datetime

# WHOIS servers
WHOIS = {
    'com': ('whois.verisign-grs.com', 43),
    'co.uk': ('whois.nic.uk', 43),
    'com.br': ('whois.registro.br', 43)
}

TIMEOUT = 10
PACING_DELAY = 1.0  # 1 second between requests
MAX_RETRIES = 3
BACKOFF_FACTOR = 2

PERMANENT_CACHE_FILE = 'permanent_results.csv'

ERROR_CODES = {
    'TIMEOUT': 'E001',
    'CONN_ERR': 'E002',
    'EMPTY_RESP': 'E003',
    'RATE_LIMIT': 'E004',
    'UNKNOWN': 'E005',
}

ERROR_PATTERNS = (
    'quota',
    'limit exceeded',
    'query rate',
    'temporarily unavailable',
    'connection limit',
    'try again later',
    'timeout',
    'whois limit exceeded',
    'exceeded your query quota',
    'exceeded allowable query limits',
    'exceeded the maximum allowable number of whois queries',
)

AVAILABLE_PATTERNS = ('no match', 'not found', 'disponivel', 'dispon\xedvel', 'available')

def check_whois(domain, tld):
    """Return (status, error_code, reason) for domain.tld"""
    server, port = WHOIS[tld]
    full_domain = f"{domain}.{tld}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((server, port))
            sock.send(f"{full_domain}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

        if not response:
            code = ERROR_CODES['EMPTY_RESP']
            reason = "Empty response from server"
            logging.error('ERROR [%s]: %s for %s', code, reason, full_domain)
            return 'error', code, reason

        text = response.decode('utf-8', errors='ignore').lower()

        # WHOIS providers may rate-limit and return error text with HTTP-like success.
        if any(pattern in text for pattern in ERROR_PATTERNS):
            code = ERROR_CODES['RATE_LIMIT']
            reason = text[:50].replace('\n', ' ').replace('\r', ' ').strip()
            logging.error('ERROR [%s]: Rate limit/quota exceeded for %s: %s', code, full_domain, reason)
            return 'error', code, reason

        if any(pattern in text for pattern in AVAILABLE_PATTERNS):
            return 'available', None, ""
        else:
            return 'not available', None, ""

    except TimeoutError:
        code = ERROR_CODES['TIMEOUT']
        reason = "Socket timeout"
        logging.exception('ERROR [%s]: %s for %s', code, reason, full_domain)
        return 'error', code, reason
    except OSError as e:
        code = ERROR_CODES['CONN_ERR']
        reason = str(e)
        logging.exception('ERROR [%s]: Connection error for %s: %s', code, full_domain, reason)
        return 'error', code, reason
    except Exception as e:
        code = ERROR_CODES['UNKNOWN']
        reason = str(e)
        logging.exception('ERROR [%s]: Unknown error for %s: %s', code, full_domain, reason)
        return 'error', code, reason

def _parse_cache_file(f):
    """Parse an open CSV file handle into the cache dictionary."""
    cache = {}
    content = f.read(1024)
    f.seek(0)
    if not content or 'domain,tld,status' not in content:
        logging.warning('Permanent cache file is missing header or empty.')
        return cache

    reader = csv.DictReader(f)
    for row in reader:
        domain, tld = row.get('domain'), row.get('tld')
        if domain and tld:
            cache[f"{domain}.{tld}"] = {
                'status': row.get('status', 'unknown'),
                'reason': row.get('reason', ''),
                'checked_at': row.get('checked_at', '')
            }
    return cache

def load_permanent_cache():
    """Load existing successful/permanent results from CSV."""
    if not os.path.exists(PERMANENT_CACHE_FILE):
        return {}
    try:
        with open(PERMANENT_CACHE_FILE, 'r', newline='') as f:
            return _parse_cache_file(f)
    except Exception as e:
        logging.exception('Failed to load permanent cache: %s', e)
    return {}

def save_to_permanent_cache(domain, tld, status, reason):
    """Append a single result to the permanent cache file."""
    file_exists = os.path.exists(PERMANENT_CACHE_FILE)
    try:
        with open(PERMANENT_CACHE_FILE, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['domain', 'tld', 'status', 'reason', 'checked_at'])
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                'domain': domain,
                'tld': tld,
                'status': status,
                'reason': reason,
                'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            f.flush()  # Ensure it's written to disk immediately
    except Exception as e:
        logging.exception('Failed to save to permanent cache for %s.%s: %s', domain, tld, e)

def get_bases(input_file):
    """Read base domains from input file."""
    try:
        with open(input_file) as f:
            bases = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.exception('%s not found', input_file)
        return []
    return bases

def initialize_environment():
    """Configure basic environment setup like logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def get_active_tlds(countries_mask):
    """
    Validate bitmask and return filtered TLD list.
    1=BR (com.br), 2=US (com), 4=UK (co.uk)
    """
    allowed_masks = range(1, 8)
    if countries_mask not in allowed_masks:
        logging.error('Invalid countries bitmask: %d. Use 1-7 (sum of: 1=BR, 2=US, 4=UK)', countries_mask)
        sys.exit(1)

    tlds = []
    if countries_mask & 1: tlds.append((1, 'com.br', 'br'))
    if countries_mask & 2: tlds.append((2, 'com', 'us'))
    if countries_mask & 4: tlds.append((4, 'co.uk', 'uk'))
    return tlds

def resolve_domain_status(base, tld, permanent_cache, failed_tlds):
    """
    Resolve availability for a single domain.tld using Priority:
    Cache -> Fail-Fast check -> Live Query.
    """
    full_domain = f"{base}.{tld}"
    status = 'unknown'
    reason = ""

    # 1. Check permanent cache first
    if full_domain in permanent_cache:
        status = permanent_cache[full_domain]['status']
        reason = permanent_cache[full_domain]['reason']
        logging.info('CACHE HIT [%s]: %s', status, full_domain)
        return status, reason

    # 2. Skip if this TLD already failed during this session
    if tld in failed_tlds:
        status = 'error'
        reason = "Skipped (previous error in this session)"
        logging.warning('SKIPPING %s: TLD .%s already failed earlier this run.', full_domain, tld)
        return status, reason

    # 3. Single attempt query with pacing
    time.sleep(PACING_DELAY)
    status, code, reason = check_whois(base, tld)

    if status != 'error':
        # SUCCESS: Add to permanent cache immediately
        save_to_permanent_cache(base, tld, status, reason)
    else:
        # ERROR: Mark TLD as failed for the rest of this run
        failed_tlds.add(tld)
        logging.error('STOPPING FUTURE ATTEMPTS for .%s due to ERROR [%s]: %s', tld, code, reason)

    return status, reason

def process_domain_row(base, tlds, countries_mask, permanent_cache, failed_tlds):
    """Build a CSV result row for a single base domain."""
    availability_mask = 0
    statuses = []
    reasons = []

    for bit, tld, _ in tlds:
        status, reason = resolve_domain_status(base, tld, permanent_cache, failed_tlds)
        if status == 'available':
            availability_mask |= bit
        statuses.append(status)
        reasons.append(reason)

    row = [base, availability_mask]
    row.extend(statuses)
    row.extend(reasons)
    return row

def write_csv(results, output_file, tlds):
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            headers = ['domain', 'availability_code'] + [t[2] for t in tlds] + [f"{t[2]}_reason" for t in tlds]
            writer.writerow(headers)
            writer.writerows(results)
        logging.info('Done. Results saved to %s', output_file)
    except Exception:
        logging.exception('Failed to write results to %s', output_file)

def print_summary(results, tlds):
    logging.info('Summary:')
    labels = [t[2].upper() for t in tlds]
    for row in results:
        # row: [domain, availability_code, ...statuses, ...reasons]
        statuses = row[2:2+len(tlds)]
        status_str = ", ".join(f"{label}={status}" for label, status in zip(labels, statuses))
        logging.info('%s: mask=%d, %s', row[0], row[1], status_str)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Domain availability checker.')
    parser.add_argument('--countries', type=int, default=7,
                        help=('Bitmask for TLDs: sum of 1 (BR), 2 (US), 4 (UK). '
                              'Examples: 7=all, 6=UK+US, 5=UK+BR, 3=US+BR, 4=UK, 2=US, 1=BR'))
    return parser.parse_args()

def main():
    args = parse_args()
    initialize_environment()

    input_file = 'domains.txt'
    output_file = 'results.csv'

    bases = get_bases(input_file)
    if not bases:
        logging.error('No domains found in %s', input_file)
        sys.exit(1)

    tlds = get_active_tlds(args.countries)
    logging.info('Checking %d domains across %d regions ...', len(bases), len(tlds))

    permanent_cache = load_permanent_cache()
    failed_tlds = set()
    final_results = []

    for base in bases:
        row = process_domain_row(base, tlds, args.countries, permanent_cache, failed_tlds)
        final_results.append(row)

    write_csv(final_results, output_file, tlds)
    print_summary(final_results, tlds)

if __name__ == '__main__':
    main()

