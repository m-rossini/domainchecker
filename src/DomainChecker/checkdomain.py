#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import csv
import logging
import os
import socket
import sys
import time
import urllib.request
from urllib.error import HTTPError
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict, Set

# RDAP Endpoints
RDAP_ENDPOINTS = {
    'com': 'https://rdap.verisign.com/com/v1/',
    'co.uk': 'https://rdap.nominet.uk/uk/v1/'
}

# Legacy WHOIS servers
WHOIS_SERVERS = {
    'com': ('whois.verisign-grs.com', 43),
    'co.uk': ('whois.nic.uk', 43)
}

TIMEOUT = 10
PACING_DELAY = 1.0
PERMANENT_CACHE_FILE = 'permanent_results.csv'
CACHE_ONLY_TLDS = ('com.br',)

ERROR_PATTERNS = ('quota', 'limit exceeded', 'query rate', 'temporarily unavailable', 'try again later')
AVAILABLE_PATTERNS = ('no match', 'not found', 'disponivel', 'available')

ERROR_CODES = {
    'TIMEOUT': 'E001',
    'CONN_ERR': 'E002',
    'EMPTY_RESP': 'E003',
    'RATE_LIMIT': 'E004',
    'UNKNOWN': 'E005',
}

@dataclass
class CheckResult:
    status: str  # 'available', 'registered', 'error', 'unknown', 'not implemented'
    reason: str = ''
    error_code: Optional[str] = None
    is_cache_hit: bool = False

# --- Protocols ---

class Protocol:
    def check(self, domain_base: str, tld: str) -> CheckResult:
        raise NotImplementedError()

class RDAPProtocol(Protocol):
    def __init__(self, endpoints: Dict[str, str], timeout: int):
        self.endpoints = endpoints
        self.timeout = timeout

    def check(self, domain_base: str, tld: str) -> CheckResult:
        endpoint = self.endpoints.get(tld)
        if not endpoint:
            return CheckResult(status='error', reason=f'No RDAP endpoint for {tld}')

        url = f'{endpoint}domain/{domain_base}.{tld}'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    return CheckResult(status='registered')
        except HTTPError as e:
            if e.code == 404:
                return CheckResult(status='available')
            return CheckResult(status='error', reason=f'HTTP Error {e.code}', error_code=ERROR_CODES['CONN_ERR'])
        except Exception as e:
            return CheckResult(status='error', reason=str(e), error_code=ERROR_CODES['UNKNOWN'])
        return CheckResult(status='unknown', reason='Unexpected response', error_code=ERROR_CODES['UNKNOWN'])

class WhoisProtocol(Protocol):
    def __init__(self, servers: Dict[str, tuple], timeout: int):
        self.servers = servers
        self.timeout = timeout

    def check(self, domain_base: str, tld: str) -> CheckResult:
        if tld not in self.servers:
            return CheckResult(status='unknown', reason=f'No WHOIS server for {tld}', error_code=ERROR_CODES['UNKNOWN'])

        server, port = self.servers[tld]
        full_domain = f'{domain_base}.{tld}'
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((server, port))
                sock.send(f'{full_domain}\r\n'.encode())
                response = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    response += chunk

            if not response:
                return CheckResult(status='error', reason='Empty response', error_code=ERROR_CODES['EMPTY_RESP'])

            text = response.decode('utf-8', errors='ignore').lower()
            if any(p in text for p in ERROR_PATTERNS):
                return CheckResult(status='error', reason='Rate limit', error_code=ERROR_CODES['RATE_LIMIT'])
            if any(p in text for p in AVAILABLE_PATTERNS):
                return CheckResult(status='available')
            return CheckResult(status='registered')
        except Exception as e:
            return CheckResult(status='error', reason=str(e), error_code=ERROR_CODES['UNKNOWN'])

# --- Storage ---

class CacheRepository:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.cache = self._load()

    def _load(self) -> Dict[str, Dict]:
        if not os.path.exists(self.file_path):
            logging.info('No permanent cache file found.')
            return {}
        cache = {}
        try:
            with open(self.file_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain, tld = row.get('domain'), row.get('tld')
                    if domain and tld:
                        # Normalize keys to lowercase for case-insensitive caching
                        cache[f"{domain.lower()}.{tld.lower()}"] = row
            logging.info('Permanent cache loaded: %d entries', len(cache))
        except Exception as e:
            logging.error('Failed to load cache: %s', e)
        return cache

    def get(self, domain_base: str, tld: str) -> Optional[CheckResult]:
        full_domain = f"{domain_base.lower()}.{tld.lower()}"
        if full_domain in self.cache:
            row = self.cache[full_domain]
            return CheckResult(
                status=row['status'],
                reason=row.get('reason', ''),
                is_cache_hit=True
            )
        return None

    def set(self, domain_base: str, tld: str, result: CheckResult):
        if result.status in ('error', 'unknown', 'not implemented'):
            return
        
        full_domain = f"{domain_base.lower()}.{tld.lower()}"
        self.cache[full_domain] = {
            'domain': domain_base.lower(),
            'tld': tld.lower(),
        }

    def persist(self):
        rows = list(self.cache.values())
        rows.sort(key=lambda x: (x['domain'].lower(), x['tld'].lower()))
        try:
            with open(self.file_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['domain', 'tld', 'status', 'reason', 'checked_at'])
                writer.writeheader()
                writer.writerows(rows)
            logging.info('Permanent cache saved and sorted: Total entries: %d', len(rows))
        except Exception as e:
            logging.error('Failed to save cache: %s', e)

# --- Handlers ---

class TLDHandler:
    def __init__(self, bit: int, tld: str, label: str):
        self.bit = bit
        self.tld = tld
        self.label = label

    def check(self, domain_base: str, repository: CacheRepository) -> CheckResult:
        # Standard cache lookup first
        result = repository.get(domain_base, self.tld)
        if result:
            logging.info('CACHE HIT [%s]: %s.%s', result.status, domain_base, self.tld)
            return result

        result = self._do_check(domain_base, repository)
        if not result.is_cache_hit:
            repository.set(domain_base, self.tld, result)
        return result

    def _do_check(self, domain_base: str, repository: CacheRepository) -> CheckResult:
        raise NotImplementedError()

class CacheOnlyHandler(TLDHandler):
    def _do_check(self, domain_base: str, repository: CacheRepository) -> CheckResult:
        return CheckResult(
            status='not implemented',
            reason=f'Not in cache ({self.tld} is cache-only)'
        )

class ActiveTLDHandler(TLDHandler):
    def __init__(self, bit: int, tld: str, label: str, protocol: Protocol, pacing_delay: float):
        super().__init__(bit, tld, label)
        self.protocol = protocol
        self.pacing_delay = pacing_delay
        self.failed = False

    def _do_check(self, domain_base: str, repository: CacheRepository) -> CheckResult:
        if self.failed:
            return CheckResult(status='error', reason='Skipped due to prior TLD error')

        full_domain = f"{domain_base}.{self.tld}"
        result = self.protocol.check(domain_base, self.tld)
        logging.info('Result for %s: %s %s', full_domain, result.status, f"({result.reason})" if result.reason else "")

        if result.status == 'error':
            self.failed = True
            logging.warning('CIRCUIT BREAKER: Stopping active checks for %s due to error.', self.tld)

        time.sleep(self.pacing_delay)
        return result

# --- Engine ---

class DomainCheckerEngine:
    def __init__(self, handlers: List[TLDHandler], repository: CacheRepository):
        self.handlers = handlers
        self.repository = repository

    def run(self, bases: List[str]) -> List[Dict]:
        logging.info('Processing %d base domains across %d handlers.', len(bases), len(self.handlers))
        results = []
        for base in bases:
            row_data = {'domain': base, 'availability_code': 0}
            for handler in self.handlers:
                result = handler.check(base, self.repository)
                row_data[handler.label] = result.status
                if result.status == 'available':
                    row_data['availability_code'] |= handler.bit
            results.append(row_data)
        return results

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    parser = argparse.ArgumentParser()
    parser.add_argument('--countries', type=int, default=7)
    args = parser.parse_args()
    logging.info('Execution started with arguments: countries=%d', args.countries)

    # Wire up components
    repository = CacheRepository(PERMANENT_CACHE_FILE)
    rdap_protocol = RDAPProtocol(RDAP_ENDPOINTS, TIMEOUT)

    handlers: List[TLDHandler] = []
    if args.countries & 1:
        handlers.append(CacheOnlyHandler(1, 'com.br', 'br'))
    if args.countries & 2:
        handlers.append(ActiveTLDHandler(2, 'com', 'us', rdap_protocol, PACING_DELAY))
    if args.countries & 4:
        handlers.append(ActiveTLDHandler(4, 'co.uk', 'uk', rdap_protocol, PACING_DELAY))

    logging.info('Regions configured: %s', [h.tld for h in handlers])

    if not os.path.exists('domains.txt'):
        logging.error("Source file 'domains.txt' not found.")
        return

    with open('domains.txt') as f:
        bases = [l.strip() for l in f if l.strip()]

    # Run engine
    engine = DomainCheckerEngine(handlers, repository)
    results = engine.run(bases)

    # Export results
    with open('results.csv', 'w', newline='') as f:
        fieldnames = ['domain', 'availability_code'] + [h.label for h in handlers]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # Finalize storage
    repository.persist()
    logging.info('Run completed. %d domains processed. Detailed results in results.csv', len(results))

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
