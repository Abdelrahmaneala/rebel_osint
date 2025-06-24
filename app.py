#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rebel OSINT Suite - Elite Intelligence Edition

import os
import re
import json
import csv
import time
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import exifread
from PIL import Image
import io
import requests
import socket
import ssl
import dns.resolver
import whois
import shodan
import builtwith
import tldextract
import urllib.parse
import xml.etree.ElementTree as ET
import ipaddress
import random
import html

# Configure logging
logging.basicConfig(
    filename='rebel_osint.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RebelOSINT')

# ///// CONFIGURATION /////
API_KEYS = {
    'shodan': os.getenv('SHODAN_API_KEY', 'YOUR_SHODAN_API_KEY'),
    'google_safe_browsing': os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', 'YOUR_GOOGLE_SAFE_BROWSING_KEY'),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY'),
    'hunterio': os.getenv('HUNTERIO_API_KEY', 'YOUR_HUNTERIO_API_KEY'),
    'ipinfo': os.getenv('IPINFO_API_KEY', 'YOUR_IPINFO_API_KEY'),
    'google_maps': os.getenv('GOOGLE_MAPS_API_KEY', 'YOUR_GOOGLE_MAPS_KEY'),
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', 'YOUR_ABUSEIPDB_KEY'),
    'hibp': os.getenv('HIBP_API_KEY', 'YOUR_HIBP_KEY')
}

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
]

class RealOSINTInvestigator:
    def __init__(self, username, domain=None, image_url=None):
        self.username = username
        self.domain = domain
        self.image_url = image_url
        self.results = {
            'username': username,
            'domain': domain,
            'social_media': {},
            'breaches': {},
            'domain_info': {},
            'ip_info': {},
            'email_addresses': [],
            'reputation': {},
            'timeline': [],
            'execution_log': [],
            'metadata': {},
            'geolocation': {},
            'reverse_image': {}
        }
        self.log_action(f"Initialized investigator for target: {username}")
        
    def log_action(self, message):
        """Log actions with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {"timestamp": timestamp, "action": message}
        self.results['timeline'].append(log_entry)
        self.results['execution_log'].append(f"{timestamp} - {message}")
    
    def get_random_headers(self):
        """Get random headers to avoid blocking"""
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def check_social_media(self):
        """Check social media presence with advanced verification"""
        platforms = {
            'twitter': f'https://twitter.com/{self.username}',
            'instagram': f'https://www.instagram.com/{self.username}',
            'facebook': f'https://www.facebook.com/{self.username}',
            'linkedin': f'https://www.linkedin.com/in/{self.username}',
            'github': f'https://github.com/{self.username}',
            'reddit': f'https://www.reddit.com/user/{self.username}',
            'pinterest': f'https://www.pinterest.com/{self.username}',
            'tiktok': f'https://www.tiktok.com/@{self.username}',
            'youtube': f'https://www.youtube.com/{self.username}',
            'telegram': f'https://t.me/{self.username}',
            'medium': f'https://medium.com/@{self.username}',
            'vimeo': f'https://vimeo.com/{self.username}',
            'flickr': f'https://www.flickr.com/people/{self.username}'
        }
        
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=10, headers=self.get_random_headers())
                
                exists = False
                confidence = "low"
                profile_data = {}
                
                if response.status_code == 200:
                    # Advanced platform-specific checks
                    if platform == 'twitter':
                        exists = 'data-screen-name=' in response.text
                        if exists:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            name_tag = soup.find('div', {'data-testid': 'UserName'})
                            if name_tag:
                                profile_data['name'] = name_tag.text.strip()
                            bio_tag = soup.find('div', {'data-testid': 'UserDescription'})
                            if bio_tag:
                                profile_data['bio'] = bio_tag.text.strip()
                            confidence = "high"
                    
                    elif platform == 'instagram':
                        exists = f'"username":"{self.username}"' in response.text
                        if exists:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            meta = soup.find('meta', property='og:description')
                            if meta:
                                profile_data['bio'] = meta.get('content', '')
                            img = soup.find('meta', property='og:image')
                            if img:
                                profile_data['avatar'] = img.get('content', '')
                            confidence = "high"
                    
                    elif platform == 'github':
                        exists = 'data-scope-id="' in response.text
                        if exists:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            name = soup.find('span', {'itemprop': 'name'})
                            if name:
                                profile_data['name'] = name.text.strip()
                            bio = soup.find('div', class_='p-note')
                            if bio:
                                profile_data['bio'] = bio.text.strip()
                            confidence = "high"
                    
                    elif platform == 'reddit':
                        exists = 'class="_2BMnTatQ5gjKGK5OWROgaG"' in response.text
                        confidence = "medium" if exists else "low"
                    
                    else:
                        exists = True
                        if self.username.lower() in response.text.lower():
                            confidence = "medium"
                
                self.results['social_media'][platform] = {
                    'url': url,
                    'exists': exists,
                    'status_code': response.status_code,
                    'confidence': confidence,
                    'profile_data': profile_data
                }
                self.log_action(f"Checked {platform}: {'Found' if exists else 'Not found'} (Confidence: {confidence})")
                
            except Exception as e:
                self.log_action(f"Error checking {platform}: {str(e)}")
                self.results['social_media'][platform] = {
                    'url': url,
                    'exists': False,
                    'error': str(e)
                }
    
    def check_breaches(self):
        """Check data breaches using Have I Been Pwned API"""
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(self.username)}?truncateResponse=false"
            headers = {
                'hibp-api-key': API_KEYS['hibp'] if API_KEYS['hibp'] != 'YOUR_HIBP_KEY' else '',
                'User-Agent': 'RebelOSINT-Suite'
            }
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                breaches = response.json()
                for breach in breaches:
                    breach['impact_score'] = self.calculate_breach_impact(breach)
                self.results['breaches'] = breaches
                self.log_action(f"Found {len(breaches)} breaches")
            elif response.status_code == 404:
                self.log_action("No breaches found")
            else:
                self.log_action(f"HIBP API error: {response.status_code}")
        except Exception as e:
            self.log_action(f"Breach check failed: {str(e)}")
    
    def calculate_breach_impact(self, breach):
        """Calculate impact score for a breach (1-10)"""
        score = 0
        # Data sensitivity scoring
        data_classes = breach.get('DataClasses', [])
        sensitive_data = ['Passwords', 'Email addresses', 'Usernames', 'Credit cards', 'Bank accounts']
        
        for data in sensitive_data:
            if data in data_classes:
                score += 3
        
        # Breach size scoring
        if breach.get('PwnCount', 0) > 1000000:
            score += 3
        elif breach.get('PwnCount', 0) > 100000:
            score += 2
        elif breach.get('PwnCount', 0) > 10000:
            score += 1
        
        # Recency scoring
        breach_date = breach.get('BreachDate', '')
        if breach_date:
            try:
                breach_year = int(breach_date.split('-')[0])
                current_year = datetime.now().year
                if current_year - breach_year <= 1:
                    score += 2
                elif current_year - breach_year <= 3:
                    score += 1
            except:
                pass
        
        return min(score, 10)  # Cap at 10
    
    def discover_emails(self):
        """Discover email addresses using Hunter.io and website scraping"""
        if not self.domain:
            self.log_action("Skipping email discovery - no domain provided")
            return
            
        emails = []
        
        # Hunter.io API
        if API_KEYS['hunterio'] != 'YOUR_HUNTERIO_API_KEY':
            try:
                url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={API_KEYS['hunterio']}"
                response = requests.get(url, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    hunter_emails = [e['value'] for e in data.get('data', {}).get('emails', [])]
                    emails.extend(hunter_emails)
                    self.log_action(f"Discovered {len(hunter_emails)} email addresses from Hunter.io")
            except Exception as e:
                self.log_action(f"Hunter.io API failed: {str(e)}")
        
        # Email pattern search from website
        try:
            website_url = f"http://{self.domain}"
            response = requests.get(website_url, headers=self.get_random_headers(), timeout=10)
            if response.status_code == 200:
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, response.text)
                valid_emails = [email for email in found_emails if email.endswith(self.domain)]
                emails.extend(valid_emails)
                self.log_action(f"Found {len(valid_emails)} emails from website content")
        except Exception as e:
            self.log_action(f"Website email extraction failed: {str(e)}")
        
        # Deduplicate and validate emails
        unique_emails = list(set(emails))
        self.results['email_addresses'] = unique_emails
        self.log_action(f"Total unique emails discovered: {len(unique_emails)}")
    
    def get_domain_info(self):
        """Get comprehensive domain information"""
        if not self.domain:
            self.log_action("Skipping domain info - no domain provided")
            return
            
        try:
            # WHOIS information
            domain_info = whois.whois(self.domain)
            self.results['domain_info']['whois'] = domain_info
            
            # DNS information
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(self.domain, record_type)
                    self.results['domain_info'][f'dns_{record_type.lower()}'] = [str(r) for r in answers]
                except Exception as e:
                    self.log_action(f"DNS {record_type} query failed: {str(e)}")
            
            # SSL certificate information
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        self.results['domain_info']['ssl_cert'] = cert
                        
                        # Parse certificate details
                        issuer = dict(x[0] for x in cert['issuer'])
                        subject = dict(x[0] for x in cert['subject'])
                        valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        
                        self.results['domain_info']['ssl_details'] = {
                            'issuer': issuer.get('organizationName', ''),
                            'subject': subject.get('commonName', ''),
                            'valid_from': valid_from.strftime('%Y-%m-%d'),
                            'valid_to': valid_to.strftime('%Y-%m-%d'),
                            'days_remaining': (valid_to - datetime.now()).days
                        }
            except Exception as e:
                self.log_action(f"SSL certificate check failed: {str(e)}")
            
            # Technology stack
            try:
                tech_stack = builtwith.parse(f"https://{self.domain}")
                self.results['domain_info']['tech_stack'] = tech_stack
            except Exception as e:
                self.log_action(f"Tech stack analysis failed: {str(e)}")
            
            # IP information
            try:
                ip_address = socket.gethostbyname(self.domain)
                self.get_ip_info(ip_address)
            except Exception as e:
                self.log_action(f"IP resolution failed: {str(e)}")
            
            # Domain age
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                domain_age = (datetime.now() - creation_date).days
                self.results['domain_info']['domain_age_days'] = domain_age
            
            self.log_action("Collected comprehensive domain information")
            
        except Exception as e:
            self.log_action(f"Domain info collection failed: {str(e)}")
    
    def get_ip_info(self, ip_address):
        """Get detailed IP information from multiple sources"""
        try:
            # Validate IP address
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                self.results['ip_info']['type'] = 'IPv4' if ip_obj.version == 4 else 'IPv6'
            except:
                self.results['ip_info']['type'] = 'Unknown'
            
            # Shodan information
            if API_KEYS['shodan'] != 'YOUR_SHODAN_API_KEY':
                try:
                    api = shodan.Shodan(API_KEYS['shodan'])
                    shodan_data = api.host(ip_address)
                    self.results['ip_info']['shodan'] = {
                        'ports': shodan_data.get('ports', []),
                        'vulnerabilities': shodan_data.get('vulns', []),
                        'services': [f"{item['port']}/{item['transport']} ({item['_shodan']['module']})" 
                                     for item in shodan_data.get('data', [])],
                        'asn': shodan_data.get('asn', ''),
                        'isp': shodan_data.get('isp', ''),
                        'last_update': shodan_data.get('last_update', '')
                    }
                except shodan.exception.APIError as e:
                    self.log_action(f"Shodan API error: {str(e)}")
            
            # ipinfo.io information
            if API_KEYS['ipinfo'] != 'YOUR_IPINFO_API_KEY':
                try:
                    url = f"https://ipinfo.io/{ip_address}/json?token={API_KEYS['ipinfo']}"
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        ipinfo_data = response.json()
                        self.results['ip_info']['ipinfo'] = {
                            'hostname': ipinfo_data.get('hostname', ''),
                            'city': ipinfo_data.get('city', ''),
                            'region': ipinfo_data.get('region', ''),
                            'country': ipinfo_data.get('country', ''),
                            'loc': ipinfo_data.get('loc', ''),
                            'org': ipinfo_data.get('org', ''),
                            'postal': ipinfo_data.get('postal', ''),
                            'timezone': ipinfo_data.get('timezone', '')
                        }
                        self.results['geolocation'] = {
                            'coordinates': ipinfo_data.get('loc', ''),
                            'map_url': f"https://maps.google.com/?q={ipinfo_data.get('loc', '')}"
                        }
                except Exception as e:
                    self.log_action(f"ipinfo.io API error: {str(e)}")
            
            # AbuseIPDB check
            if API_KEYS['abuseipdb'] != 'YOUR_ABUSEIPDB_KEY':
                try:
                    url = 'https://api.abuseipdb.com/api/v2/check'
                    headers = {
                        'Key': API_KEYS['abuseipdb'],
                        'Accept': 'application/json'
                    }
                    params = {
                        'ipAddress': ip_address,
                        'maxAgeInDays': '90'
                    }
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                    if response.status_code == 200:
                        abuse_data = response.json().get('data', {})
                        self.results['reputation']['abuseipdb'] = {
                            'abuse_confidence': abuse_data.get('abuseConfidenceScore', 0),
                            'reports': abuse_data.get('totalReports', 0),
                            'isp': abuse_data.get('isp', ''),
                            'domain': abuse_data.get('domain', ''),
                            'last_reported': abuse_data.get('lastReportedAt', '')
                        }
                except Exception as e:
                    self.log_action(f"AbuseIPDB API error: {str(e)}")
            
            self.log_action(f"Collected IP information for {ip_address}")
            
        except Exception as e:
            self.log_action(f"IP info collection failed: {str(e)}")
    
    def check_reputation(self):
        """Check domain and IP reputation from multiple sources"""
        if not self.domain:
            self.log_action("Skipping reputation check - no domain provided")
            return
            
        try:
            # Google Safe Browsing
            if API_KEYS['google_safe_browsing'] != 'YOUR_GOOGLE_SAFE_BROWSING_KEY':
                url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEYS['google_safe_browsing']}"
                payload = {
                    "client": {
                        "clientId": "RebelOSINT",
                        "clientVersion": "1.0"
                    },
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": f"http://{self.domain}"}, {"url": f"https://{self.domain}"}]
                    }
                }
                
                response = requests.post(url, json=payload, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    threats = data.get('matches', [])
                    self.results['reputation']['google_safe_browsing'] = threats
                    self.log_action(f"Google Safe Browsing: {'Threat detected' if threats else 'No threats found'}")
            
            # VirusTotal
            if API_KEYS['virustotal'] != 'YOUR_VIRUSTOTAL_API_KEY':
                try:
                    url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
                    headers = {'x-apikey': API_KEYS['virustotal']}
                    response = requests.get(url, headers=headers, timeout=15)
                    if response.status_code == 200:
                        vt_data = response.json()
                        stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        self.results['reputation']['virustotal'] = {
                            'harmless': stats.get('harmless', 0),
                            'malicious': stats.get('malicious', 0),
                            'suspicious': stats.get('suspicious', 0),
                            'undetected': stats.get('undetected', 0),
                            'reputation': vt_data.get('data', {}).get('attributes', {}).get('reputation', 0),
                            'last_analysis_date': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_date', '')
                        }
                        self.log_action(f"VirusTotal: {stats.get('malicious', 0)} malicious detections")
                except Exception as e:
                    self.log_action(f"VirusTotal API error: {str(e)}")
            
            # Security Headers Check
            try:
                response = requests.get(f"https://{self.domain}", timeout=10, headers=self.get_random_headers())
                security_headers = {}
                important_headers = [
                    'Content-Security-Policy',
                    'Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Referrer-Policy',
                    'Permissions-Policy'
                ]
                
                for header in important_headers:
                    if header in response.headers:
                        security_headers[header] = response.headers[header]
                    else:
                        security_headers[header] = "MISSING"
                
                self.results['reputation']['security_headers'] = security_headers
                self.log_action("Security headers analyzed")
            except Exception as e:
                self.log_action(f"Security headers check failed: {str(e)}")
            
            self.log_action("Completed reputation checks")
            
        except Exception as e:
            self.log_action(f"Reputation check failed: {str(e)}")
    
    def reverse_image_search(self):
        """Perform reverse image search using multiple engines"""
        if not self.image_url:
            return {}
            
        try:
            results = {'google': [], 'bing': [], 'tineye': []}
            
            # Google Reverse Image Search
            cse_id = os.getenv('GOOGLE_CSE_ID', 'YOUR_GOOGLE_CSE_ID')
            api_key = os.getenv('GOOGLE_API_KEY', 'YOUR_GOOGLE_API_KEY')
            
            if cse_id != 'YOUR_GOOGLE_CSE_ID' and api_key != 'YOUR_GOOGLE_API_KEY':
                try:
                    url = "https://www.googleapis.com/customsearch/v1"
                    params = {
                        'q': self.image_url,
                        'searchType': 'image',
                        'cx': cse_id,
                        'key': api_key,
                        'num': 5
                    }
                    
                    response = requests.get(url, params=params, timeout=15)
                    if response.status_code == 200:
                        google_data = response.json()
                        for item in google_data.get('items', [])[:5]:
                            results['google'].append({
                                'title': item.get('title', 'No title'),
                                'link': item.get('link', '#'),
                                'displayLink': item.get('displayLink', '')
                            })
                except Exception as e:
                    self.log_action(f"Google image search failed: {str(e)}")
            
            # Bing Image Search (HTML scraping)
            try:
                bing_url = f"https://www.bing.com/images/search?q=imgurl:{urllib.parse.quote(self.image_url)}"
                response = requests.get(bing_url, headers=self.get_random_headers(), timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for result in soup.select('.iuscp')[:5]:
                        title = result.select_one('.inflnk')
                        source = result.select_one('.iusc')
                        if title and source:
                            try:
                                source_data = json.loads(source.get('m', '{}'))
                                results['bing'].append({
                                    'title': title.get('aria-label', 'No title'),
                                    'link': source_data.get('purl', '#'),
                                    'displayLink': urllib.parse.urlparse(source_data.get('purl', '')).netloc
                                })
                            except:
                                continue
            except Exception as e:
                self.log_action(f"Bing image search failed: {str(e)}")
            
            # TinEye Reverse Image Search (HTML scraping)
            try:
                tineye_url = f"https://tineye.com/search?url={urllib.parse.quote(self.image_url)}"
                response = requests.get(tineye_url, headers=self.get_random_headers(), timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for result in soup.select('.match')[:5]:
                        title = result.select_one('.match__title')
                        source = result.select_one('.match__image__link')
                        if title and source:
                            results['tineye'].append({
                                'title': title.text.strip(),
                                'link': source.get('href', '#'),
                                'displayLink': urllib.parse.urlparse(source.get('href', '')).netloc
                            })
            except Exception as e:
                self.log_action(f"TinEye image search failed: {str(e)}")
            
            return results
        except Exception as e:
            self.log_action(f"Reverse image search failed: {str(e)}")
            return {}
    
    def execute_full_investigation(self):
        """Run all investigation modules"""
        start_time = time.time()
        
        # Run core modules
        self.check_social_media()
        self.check_breaches()
        
        if self.domain:
            self.discover_emails()
            self.get_domain_info()
            self.check_reputation()
        
        if self.image_url:
            self.results['reverse_image'] = self.reverse_image_search()
        
        # Add metadata
        end_time = time.time()
        self.results['metadata'] = {
            'investigation_time': round(end_time - start_time, 2),
            'timestamp': datetime.now().isoformat(),
            'modules_executed': list(filter(None, [
                'social_media',
                'breaches',
                'emails' if self.domain else '',
                'domain_info' if self.domain else '',
                'reputation' if self.domain else '',
                'reverse_image' if self.image_url else ''
            ]))
        }
        
        self.log_action(f"Full investigation completed in {self.results['metadata']['investigation_time']} seconds")
        return self.results

# ///// FLASK WEB INTERFACE /////
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Simple user database
users = {
    'rebel': generate_password_hash('hunter123')
}

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 Error: {str(e)}")
    return render_template('error.html', error_code=500, message="Internal server error"), 500

@app.before_request
def require_login():
    if request.endpoint not in ['login', 'static', 'home', 'error'] and 'user' not in session:
        return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            if username in users and check_password_hash(users[username], password):
                session['user'] = username
                return redirect(url_for('dashboard'))
            return render_template('login.html', error='Invalid credentials')
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return render_template('error.html', error_code=500, message="Login failed")

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/investigate', methods=['POST'])
def investigate():
    try:
        if 'user' not in session:
            return redirect(url_for('login'))
            
        username = request.form['username']
        domain = request.form.get('domain', '')
        image_url = request.form.get('image_url', '')
        
        investigator = RealOSINTInvestigator(username, domain, image_url)
        results = investigator.execute_full_investigation()
        
        # Store results in session
        session['last_investigation'] = results
        session['username'] = username
        return render_template('results.html', results=results)
    except Exception as e:
        logger.exception(f"Investigation failed: {str(e)}")
        return render_template('error.html', error_code=500, message=f"Investigation failed: {str(e)}")

@app.route('/export/json')
def export_json():
    if 'last_investigation' not in session or 'user' not in session:
        return redirect(url_for('dashboard'))
    
    return jsonify(session['last_investigation'])

@app.route('/export/csv')
def export_csv():
    if 'last_investigation' not in session or 'user' not in session:
        return redirect(url_for('dashboard'))
    
    results = session['last_investigation']
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Type', 'Platform', 'URL', 'Exists', 'Status'])
    
    # Write social media data
    for platform, data in results.get('social_media', {}).items():
        writer.writerow([
            'Social Media',
            platform,
            data['url'],
            data.get('exists', False),
            data.get('status_code', '')
        ])
    
    # Write breach data
    for breach in results.get('breaches', []):
        writer.writerow([
            'Breach',
            breach.get('Name', ''),
            breach.get('Domain', ''),
            True,
            breach.get('BreachDate', '')
        ])
    
    # Write email data
    for email in results.get('email_addresses', []):
        writer.writerow([
            'Email',
            '',
            email,
            True,
            ''
        ])
    
    return app.response_class(
        response=output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename={session["username"]}_report.csv'}
    )

@app.route('/export/txt')
def export_txt():
    if 'last_investigation' not in session or 'user' not in session:
        return redirect(url_for('dashboard'))
    
    results = session['last_investigation']
    text = f"Rebel OSINT Report - {results['username']}\n"
    text += "="*50 + "\n\n"
    
    # Social media results
    text += "Social Media Presence:\n"
    for platform, data in results.get('social_media', {}).items():
        status = "Found" if data.get('exists') else "Not found"
        text += f"- {platform}: {status} ({data['url']})\n"
    
    # Breach results
    text += "\nData Breaches:\n"
    if results.get('breaches'):
        for breach in results['breaches']:
            text += f"- {breach['Name']} ({breach['BreachDate']}): {breach['Description']}\n"
    else:
        text += "No known breaches found\n"
    
    # Email results
    if results.get('email_addresses'):
        text += "\nEmail Addresses:\n"
        for email in results['email_addresses']:
            text += f"- {email}\n"
    
    # Domain info
    if results.get('domain_info'):
        text += "\nDomain Information:\n"
        domain_info = results['domain_info']
        text += f"- Registrar: {domain_info['whois'].get('registrar', '')}\n"
        text += f"- Creation Date: {domain_info['whois'].get('creation_date', '')}\n"
        text += f"- Expiration Date: {domain_info['whois'].get('expiration_date', '')}\n"
        
        if domain_info.get('dns_a'):
            text += f"- IP Addresses: {', '.join(domain_info['dns_a'])}\n"
    
    # Reverse image results
    if results.get('reverse_image'):
        text += "\nReverse Image Search Results:\n"
        for engine, items in results['reverse_image'].items():
            if items:
                text += f"- {engine.capitalize()}:\n"
                for i, item in enumerate(items, 1):
                    text += f"  {i}. {item.get('title', 'No title')}\n"
                    text += f"     URL: {item.get('link', '')}\n"
    
    return app.response_class(
        response=text,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment;filename={session["username"]}_report.txt'}
    )

def create_template(file_path, content):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            f.write(content)

if __name__ == '__main__':
    # Create necessary templates
    templates = {
        'error.html': """<!DOCTYPE html>
<html>
<head>
    <title>Error {{ error_code }}</title>
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            background: #0f0f23; 
            color: #ff5555; 
            text-align: center; 
            padding: 50px;
        }
        .error-box { 
            border: 2px solid #ff5555; 
            padding: 30px; 
            max-width: 600px; 
            margin: 0 auto;
            background: #1a1a2e;
            border-radius: 10px;
        }
        h1 { font-size: 3em; margin-bottom: 20px; }
        p { font-size: 1.2em; margin: 20px 0; }
        a {
            color: #00ff00;
            text-decoration: none;
            border: 1px solid #00ff00;
            padding: 10px 20px;
            border-radius: 5px;
            display: inline-block;
            margin-top: 20px;
        }
        a:hover {
            background: #00ff00;
            color: #0f0f23;
        }
    </style>
</head>
<body>
    <div class="error-box">
        <h1>🚨 ERROR {{ error_code }} 🚨</h1>
        <p>{{ message }}</p>
        <p>Please check logs or try again</p>
        <a href="/">Return to Home</a>
    </div>
</body>
</html>""",
        
        'login.html': """<!DOCTYPE html>
<html>
<head>
    <title>Rebel OSINT - Login</title>
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            background: #0f0f23; 
            color: #00ff00; 
            text-align: center; 
            padding: 50px;
        }
        .container { 
            width: 300px; 
            margin: 100px auto; 
            border: 1px solid #00ff00;
            padding: 30px;
            border-radius: 10px;
            background: #1a1a2e;
        }
        h1 { margin-bottom: 30px; }
        input, button { 
            width: 100%; 
            padding: 12px; 
            margin: 10px 0; 
            background: #0f0f23; 
            color: #00ff00; 
            border: 1px solid #00ff00; 
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
        button {
            background: #00ff00;
            color: #0f0f23;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        button:hover {
            background: #0f0f23;
            color: #00ff00;
        }
        .error { 
            color: #ff5555; 
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Rebel OSINT Suite</h1>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <p style="margin-top: 20px;">Default: rebel / hunter123</p>
    </div>
</body>
</html>""",
        
        'dashboard.html': """<!DOCTYPE html>
<html>
<head>
    <title>Rebel OSINT - Dashboard</title>
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            background: #0f0f23; 
            color: #00ff00; 
            text-align: center; 
            padding: 50px;
        }
        .container { 
            width: 80%; 
            margin: auto; 
        }
        .card { 
            background: #1a1a2e; 
            border: 1px solid #00ff00; 
            padding: 20px; 
            margin: 20px 0;
            border-radius: 10px;
        }
        input, button, textarea { 
            padding: 10px; 
            margin: 5px 0; 
            background: #0f0f23; 
            color: #00ff00; 
            border: 1px solid #00ff00; 
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            width: 100%;
            box-sizing: border-box;
        }
        button {
            background: #00ff00;
            color: #0f0f23;
            font-weight: bold;
            cursor: pointer;
            padding: 10px 20px;
            width: auto;
        }
        .form-group {
            margin: 15px 0;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        .logout-btn {
            position: absolute;
            top: 20px;
            right: 20px;
        }
    </style>
</head>
<body>
    <a href="/logout" class="logout-btn">Logout</a>
    <div class="container">
        <h1>Welcome, {{ user }}!</h1>
        <div class="card">
            <h2>OSINT Investigator</h2>
            <form action="/investigate" method="POST">
                <div class="form-group">
                    <label for="username">Target Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="domain">Target Domain (Optional):</label>
                    <input type="text" id="domain" name="domain">
                </div>
                
                <div class="form-group">
                    <label for="image_url">Profile Image URL (Optional):</label>
                    <input type="text" id="image_url" name="image_url">
                </div>
                
                <button type="submit">Start Investigation</button>
            </form>
        </div>
    </div>
</body>
</html>""",
        
        'results.html': """<!DOCTYPE html>
<html>
<head>
    <title>Rebel OSINT - Results</title>
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            background: #0f0f23; 
            color: #00ff00; 
            padding: 20px;
        }
        .container { 
            width: 90%; 
            margin: auto; 
        }
        .card { 
            background: #1a1a2e; 
            border: 1px solid #00ff00; 
            padding: 15px; 
            margin: 15px 0;
            border-radius: 5px;
        }
        h1, h2, h3 { 
            color: #00ffff; 
        }
        .found { 
            color: #00ff00; 
        }
        .not-found { 
            color: #ff5555; 
        }
        .export-buttons { 
            margin: 20px 0; 
        }
        .export-buttons button { 
            background: #00ff00; 
            color: #0f0f23; 
            border: none; 
            padding: 10px 15px; 
            margin: 0 10px; 
            border-radius: 5px; 
            cursor: pointer; 
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            border: 1px solid #00ff00;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #1a1a2e;
        }
        .positive {
            color: #00ff00;
        }
        .negative {
            color: #ff5555;
        }
        .search-results {
            margin-left: 20px;
        }
        .search-results a {
            color: #00ffff;
            text-decoration: none;
        }
        .search-results a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Rebel OSINT Report</h1>
        <h2>Target: {{ results.username }}</h2>
        
        <div class="export-buttons">
            <button onclick="location.href='/export/json'">Export JSON</button>
            <button onclick="location.href='/export/csv'">Export CSV</button>
            <button onclick="location.href='/export/txt'">Export TXT</button>
            <button onclick="location.href='/dashboard'">New Search</button>
        </div>
        
        <div class="card">
            <h2>Social Media Presence</h2>
            <table>
                <tr>
                    <th>Platform</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Confidence</th>
                </tr>
                {% for platform, data in results.social_media.items() %}
                <tr>
                    <td>{{ platform }}</td>
                    <td><a href="{{ data.url }}" target="_blank" style="color: #00ffff;">{{ data.url }}</a></td>
                    <td class="{% if data.exists %}positive{% else %}negative{% endif %}">
                        {% if data.exists %}Found{% else %}Not Found{% endif %}
                    </td>
                    <td>{{ data.confidence }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        
        {% if results.breaches %}
        <div class="card">
            <h2>Data Breaches</h2>
            <table>
                <tr>
                    <th>Breach Name</th>
                    <th>Date</th>
                    <th>Impact Score</th>
                    <th>Description</th>
                </tr>
                {% for breach in results.breaches %}
                <tr>
                    <td>{{ breach.Name }}</td>
                    <td>{{ breach.BreachDate }}</td>
                    <td>{{ breach.impact_score }}/10</td>
                    <td>{{ breach.Description }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if results.email_addresses %}
        <div class="card">
            <h2>Email Addresses</h2>
            <ul>
                {% for email in results.email_addresses %}
                <li>{{ email }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        {% if results.domain_info %}
        <div class="card">
            <h2>Domain Information</h2>
            <h3>WHOIS Data</h3>
            <p><strong>Registrar:</strong> {{ results.domain_info.whois.registrar }}</p>
            <p><strong>Creation Date:</strong> {{ results.domain_info.whois.creation_date }}</p>
            <p><strong>Expiration Date:</strong> {{ results.domain_info.whois.expiration_date }}</p>
            <p><strong>Domain Age:</strong> {{ results.domain_info.domain_age_days }} days</p>
            
            <h3>SSL Certificate</h3>
            {% if results.domain_info.ssl_details %}
            <p><strong>Issuer:</strong> {{ results.domain_info.ssl_details.issuer }}</p>
            <p><strong>Valid From:</strong> {{ results.domain_info.ssl_details.valid_from }}</p>
            <p><strong>Valid To:</strong> {{ results.domain_info.ssl_details.valid_to }}</p>
            <p><strong>Days Remaining:</strong> {{ results.domain_info.ssl_details.days_remaining }}</p>
            {% endif %}
            
            <h3>DNS Records</h3>
            {% if results.domain_info.dns_a %}
            <p><strong>A Records:</strong> {{ results.domain_info.dns_a|join(', ') }}</p>
            {% endif %}
            {% if results.domain_info.dns_mx %}
            <p><strong>MX Records:</strong> {{ results.domain_info.dns_mx|join(', ') }}</p>
            {% endif %}
            
            {% if results.domain_info.tech_stack %}
            <h3>Technology Stack</h3>
            <ul>
                {% for tech, details in results.domain_info.tech_stack.items() %}
                <li><strong>{{ tech }}:</strong> {{ details|join(', ') }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endif %}
        
        {% if results.reputation %}
        <div class="card">
            <h2>Reputation Analysis</h2>
            {% if results.reputation.virustotal %}
            <h3>VirusTotal</h3>
            <p><strong>Reputation Score:</strong> {{ results.reputation.virustotal.reputation }}</p>
            <p><strong>Malicious Detections:</strong> {{ results.reputation.virustotal.malicious }}</p>
            {% endif %}
            
            {% if results.reputation.google_safe_browsing %}
            <h3>Google Safe Browsing</h3>
            <p><strong>Threats Detected:</strong> {{ results.reputation.google_safe_browsing|length }}</p>
            {% endif %}
            
            {% if results.reputation.security_headers %}
            <h3>Security Headers</h3>
            <table>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                </tr>
                {% for header, value in results.reputation.security_headers.items() %}
                <tr>
                    <td>{{ header }}</td>
                    <td class="{% if value == 'MISSING' %}negative{% else %}positive{% endif %}">
                        {{ value }}
                    </td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
        </div>
        {% endif %}
        
        {% if results.reverse_image %}
        <div class="card">
            <h2>Reverse Image Search Results</h2>
            {% for engine, items in results.reverse_image.items() %}
                {% if items %}
                <h3>{{ engine|capitalize }}</h3>
                <div class="search-results">
                    {% for item in items %}
                    <p>
                        <strong>{{ loop.index }}.</strong> 
                        <a href="{{ item.link }}" target="_blank">{{ item.title }}</a>
                        <br><small>{{ item.displayLink }}</small>
                    </p>
                    {% endfor %}
                </div>
                {% endif %}
            {% endfor %}
        </div>
        {% endif %}
        
        <div class="card">
            <h2>Investigation Timeline</h2>
            <ul>
                {% for entry in results.timeline %}
                <li><strong>{{ entry.timestamp }}</strong> - {{ entry.action }}</li>
                {% endfor %}
            </ul>
        </div>
    </div>
</body>
</html>"""
    }
    
    for name, content in templates.items():
        create_template(f'templates/{name}', content)
    
    print("\n🔥 Rebel OSINT Suite - Elite Intelligence Edition 🔥")
    print("Access the interface at: https://localhost:5000")
    print("Login with: rebel / hunter123\n")
    
    # Run the app
    try:
        app.run(host='0.0.0.0', port=5000, ssl_context='adhoc', threaded=True)
    except Exception as e:
        logger.exception(f"Failed to start app: {str(e)}")
        print(f"Failed to start app: {str(e)}")
