# ioc_checker.py - Version améliorée
import requests
import json
import os
import hashlib
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

CACHE_FILE = 'ioc_cache.json'
CACHE_TTL_HOURS = 24

# Sources multiples d'IOCs
IOC_SOURCES = {
    'otx': {
        'url': 'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
        'headers_func': lambda: {'X-OTX-API-KEY': os.environ.get('OTX_API_KEY', '')},
        'parser': 'parse_otx'
    },
    'virustotal': {
        'url': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
        'headers_func': lambda: {},
        'params_func': lambda ip: {'apikey': os.environ.get('VT_API_KEY', ''), 'ip': ip},
        'parser': 'parse_virustotal'
    }
}

def load_cache():
    """Charge le cache depuis le fichier"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Erreur lors du chargement du cache: {e}")
    return {}

def save_cache(cache):
    """Sauvegarde le cache dans le fichier"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde du cache: {e}")

def is_cache_valid(entry):
    """Vérifie si une entrée de cache est encore valide"""
    try:
        expiry = datetime.fromisoformat(entry['expiry'])
        return datetime.utcnow() < expiry
    except:
        return False

def parse_otx(data):
    """Parse la réponse OTX"""
    reputation = data.get('reputation', 0)
    pulses = len(data.get('pulse_info', {}).get('pulses', [])) if data.get('pulse_info') else 0
    
    return {
        'is_malicious': reputation > 0 or pulses > 0,
        'reputation_score': reputation,
        'threat_count': pulses,
        'source': 'OTX'
    }

def parse_virustotal(data):
    """Parse la réponse VirusTotal"""
    detected_urls = data.get('detected_urls', [])
    detected_samples = data.get('detected_samples', [])
    
    return {
        'is_malicious': len(detected_urls) > 0 or len(detected_samples) > 0,
        'detected_urls_count': len(detected_urls),
        'detected_samples_count': len(detected_samples),
        'source': 'VirusTotal'
    }

def query_ioc_source(ip, source_name, source_config):
    """Interroge une source d'IOC"""
    try:
        url = source_config['url'].format(ip=ip)
        headers = source_config['headers_func']()
        
        params = {}
        if 'params_func' in source_config:
            params = source_config['params_func'](ip)
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            parser_name = source_config['parser']
            
            if parser_name == 'parse_otx':
                return parse_otx(data)
            elif parser_name == 'parse_virustotal':
                return parse_virustotal(data)
        
        return None
        
    except Exception as e:
        logger.warning(f"Erreur lors de la requête {source_name} pour {ip}: {e}")
        return None

def is_malicious_ip(ip):
    """Vérifie si une IP est malveillante (fonction principale)"""
    cache = load_cache()
    
    # Vérification du cache
    if ip in cache and is_cache_valid(cache[ip]):
        return cache[ip]['is_malicious']
    
    # Interroger les sources
    is_malicious = False
    reputation_data = {}
    
    for source_name, source_config in IOC_SOURCES.items():
        result = query_ioc_source(ip, source_name, source_config)
        if result:
            reputation_data[source_name] = result
            if result['is_malicious']:
                is_malicious = True
    
    # Mise à jour du cache
    cache[ip] = {
        'is_malicious': is_malicious,
        'reputation_sources': reputation_data,
        'checked_at': datetime.utcnow().isoformat(),
        'expiry': (datetime.utcnow() + timedelta(hours=CACHE_TTL_HOURS)).isoformat()
    }
    
    save_cache(cache)
    return is_malicious

def get_ip_reputation(ip):
    """Récupère la réputation complète d'une IP"""
    cache = load_cache()
    
    if ip in cache and is_cache_valid(cache[ip]):
        return cache[ip]['reputation_sources']
    
    # Si pas en cache, déclencher la vérification
    is_malicious_ip(ip)
    
    # Recharger le cache
    cache = load_cache()
    return cache.get(ip, {}).get('reputation_sources', {})

def bulk_check_ips(ip_list):
    """Vérifie une liste d'IPs en lot"""
    results = {}
    
    for ip in ip_list:
        results[ip] = {
            'is_malicious': is_malicious_ip(ip),
            'reputation': get_ip_reputation(ip)
        }
    
    return results

if __name__ == '__main__':
    # Test
    test_ip = "192.0.2.1"
    result = is_malicious_ip(test_ip)
    reputation = get_ip_reputation(test_ip)
    
    print(f"IP {test_ip}:")
    print(f"  Malicious: {result}")
    print(f"  Reputation: {json.dumps(reputation, indent=2)}")