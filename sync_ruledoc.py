#!/usr/bin/env python3
# sync_ruledoc.py
"""
FireMon Rule Documentation Sync Script
Syncs rule documentation (props) from management stations to their child devices.

Usage:
    python3 sync_ruledoc.py                    # Sync all management stations
    python3 sync_ruledoc.py --mgmt-id 1289     # Sync specific management station
    python3 sync_ruledoc.py --test             # Test connection
    python3 sync_ruledoc.py --help             # Show help

Configuration via environment variables:
    export FIREMON_URL="https://your_server.com"
    export FIREMON_USER="username"
    export FIREMON_PASSWORD='password'
"""

from __future__ import annotations

import os
import sys
import glob
import json
import logging
import warnings
import argparse
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Any, Optional, Tuple, Set

# Global variables for modules that may not be available initially
requests = None
HTTPAdapter = None
Retry = None


# ============================================================================
# FIREMON ENVIRONMENT INITIALIZATION
# ============================================================================

def add_firemon_paths() -> None:
    """Dynamically add FireMon package paths based on available Python versions."""
    base_path = '/usr/lib/firemon/devpackfw/lib'
    
    # First, try to find any python3.* directories
    if os.path.exists(base_path):
        python_dirs = glob.glob(os.path.join(base_path, 'python3.*'))
        python_dirs.sort(reverse=True)  # Sort in descending order to try newest first
        
        for python_dir in python_dirs:
            site_packages = os.path.join(python_dir, 'site-packages')
            if os.path.exists(site_packages) and site_packages not in sys.path:
                sys.path.append(site_packages)
                logging.debug(f"Added Python path: {site_packages}")
    
    # Also try common Python version patterns
    for minor_version in range(20, 5, -1):  # Try from 3.20 down to 3.6
        path = f'/usr/lib/firemon/devpackfw/lib/python3.{minor_version}/site-packages'
        if os.path.exists(path) and path not in sys.path:
            sys.path.append(path)
            logging.debug(f"Added Python path: {path}")


def initialize_firemon_environment() -> bool:
    """Initialize FireMon environment and import required modules."""
    global requests, HTTPAdapter, Retry
    
    # Add FireMon paths dynamically
    add_firemon_paths()
    
    # Try importing requests
    if requests is None:
        try:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            logging.info("Successfully imported requests module")
        except ImportError:
            logging.error("Failed to import requests module after adding all possible paths")
            print("Error: Could not import requests module. Please check FireMon installation.")
            return False
    
    # Suppress warnings for unverified HTTPS requests
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    try:
        from urllib3.exceptions import InsecureRequestWarning
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    except ImportError:
        pass
    
    return True


# ============================================================================
# CONFIGURATION
# ============================================================================

def load_config() -> Dict[str, Any]:
    """Load configuration with environment variable support for sensitive data."""
    return {
        'url': os.environ.get('FIREMON_URL', 'https://demo.firemon.xyz'),
        'user': os.environ.get('FIREMON_USER', 'username'),
        'password': os.environ.get('FIREMON_PASSWORD', 'password'),
        'page_size': int(os.environ.get('FIREMON_PAGE_SIZE', '100')),
        'log_filename': os.environ.get('FIREMON_LOG_FILE', './sync_ruledoc.log'),
        'log_level': getattr(logging, os.environ.get('FIREMON_LOG_LEVEL', 'INFO')),
        'log_max_bytes': int(os.environ.get('FIREMON_LOG_MAX_BYTES', '10485760')),  # 10MB default
        'log_backup_count': int(os.environ.get('FIREMON_LOG_BACKUP_COUNT', '5')),  # Keep 5 backups
        'domain_id': int(os.environ.get('FIREMON_DOMAIN_ID', '1')),
        'verify_ssl': os.environ.get('FIREMON_VERIFY_SSL', 'false').lower() == 'true'
    }


def setup_logging(log_filename: str, log_level: int, max_bytes: int = 10485760, backup_count: int = 5) -> None:
    """Configure logging with proper format and rotation."""
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create rotating file handler (10MB default, keep 5 backups)
    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


# ============================================================================
# FIREMON API CLIENT
# ============================================================================

class FireMonClient:
    """REST API client for FireMon Security Manager."""
    
    def __init__(self, base_url: str, user: str, password: str, 
                 page_size: int = 100, verify_ssl: bool = False):
        """
        Initialize FireMon client.
        
        Args:
            base_url: Base URL of FireMon server (e.g., https://demo.firemon.xyz)
            user: Username for authentication
            password: Password for authentication
            page_size: Default page size for paginated requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/securitymanager/api"
        self.user = user
        self.password = password
        self.page_size = page_size
        self.verify_ssl = verify_ssl
        self.auth_token = None
        self.session = self._create_session()
        
        # Authenticate and get token
        self._authenticate()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry = Retry(
            total=3,
            read=3,
            connect=3,
            backoff_factor=0.3,
            status_forcelist=(500, 502, 504)
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = self.verify_ssl
        
        # Set Basic Auth for initial authentication
        session.auth = (self.user, self.password)
        session.headers = {'Content-Type': 'application/json'}
        return session
    
    def _authenticate(self) -> None:
        """Authenticate with FireMon and get auth token."""
        logon_data = {
            'username': self.user,
            'password': self.password
        }
        
        # Step 1: Validate credentials using Basic Auth
        try:
            verify_url = f'{self.api_url}/authentication/validate'
            verify_response = self.session.post(
                verify_url,
                data=json.dumps(logon_data),
                verify=self.verify_ssl
            )
            
            if verify_response.status_code != 200:
                error_msg = f"Authentication validation failed with status {verify_response.status_code}"
                if verify_response.text:
                    error_msg += f": {verify_response.text}"
                raise Exception(error_msg)
            
            auth_result = verify_response.json()
            auth_status = auth_result.get('authStatus', '')
            
            if auth_status != 'AUTHORIZED':
                raise Exception(f"Authorization failed. Status: {auth_status}")
            
            logging.info("Authentication validation successful")
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Authentication validation failed: {e}")
            raise
        
        # Step 2: Get authentication token
        try:
            login_url = f'{self.api_url}/authentication/login'
            login_response = self.session.post(
                login_url,
                data=json.dumps(logon_data),
                verify=self.verify_ssl
            )
            
            if login_response.status_code != 200:
                error_msg = f"Login failed with status {login_response.status_code}"
                if login_response.text:
                    error_msg += f": {login_response.text}"
                raise Exception(error_msg)
            
            login_result = login_response.json()
            token = login_result.get('token')
            
            if not token:
                raise Exception(f"No token received during authentication")
            
            # Store token and update session headers
            self.auth_token = token
            self.session.headers['X-FM-Auth-Token'] = token
            
            # Remove Basic Auth after getting token
            self.session.auth = None
            
            logging.info(f"Authentication successful")
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to obtain authentication token: {e}")
            raise
    
    def _handle_response(self, response: requests.Response) -> Any:
        """Handle API response, re-authenticating if token expired."""
        # Check if token expired and re-authenticate if needed
        if response.status_code == 401:
            logging.info("Token expired, re-authenticating...")
            self._authenticate()
            return None  # Signal caller to retry
        
        response.raise_for_status()
        
        if response.text:
            try:
                return response.json()
            except json.JSONDecodeError:
                return {'status': 'success'}
        return {'status': 'success'}
    
    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform GET request with automatic retry on auth failure."""
        for attempt in range(2):  # Try twice (once after re-auth)
            response = self.session.get(url, params=params, verify=self.verify_ssl)
            result = self._handle_response(response)
            if result is not None:  # Not a 401 retry
                return result
        
        # If we get here, retry failed
        raise Exception("Failed to authenticate after retry")
    
    def _put(self, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform PUT request with automatic retry on auth failure."""
        for attempt in range(2):  # Try twice (once after re-auth)
            response = self.session.put(url, json=data, verify=self.verify_ssl)

            # Log request details for debugging
            if response.status_code >= 400:
                logging.debug(f"PUT request to {url}")
                logging.debug(f"Request payload: {json.dumps(data, indent=2)}")
                logging.debug(f"Response status: {response.status_code}")
                logging.debug(f"Response body: {response.text}")

            result = self._handle_response(response)
            if result is not None:  # Not a 401 retry
                return result

        # If we get here, retry failed
        raise Exception("Failed to authenticate after retry")
    
    def _paged_get(self, url: str, page_size: Optional[int] = None) -> List[Dict[str, Any]]:
        """Perform paginated GET request."""
        if page_size is None:
            page_size = self.page_size
        
        results = []
        page_index = 0
        total = page_size + 1
        separator = '&' if '?' in url else '?'
        
        while len(results) < total:
            paged_url = f'{url}{separator}page={page_index}&pageSize={page_size}'
            
            data = self._get(paged_url)
            
            results.extend(data.get('results', []))
            page_index += 1
            total = data.get('total', 0)
            
            if not data.get('results'):  # No more results
                break
        
        return results
    
    def search_devices(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for devices using SIQL query.
        
        Args:
            query: SIQL query string (e.g., "device{type='DEVICE_MGR'}")
            
        Returns:
            List of device dictionaries
        """
        url = f'{self.api_url}/siql/device/paged-search'
        
        logging.debug(f"Searching devices with query: {query}")
        return self._paged_get(f"{url}?q={query}&sort=name")
    
    def search_rules(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for security rules using SIQL query.
        
        Args:
            query: SIQL query string
            
        Returns:
            List of rule dictionaries
        """
        url = f'{self.api_url}/siql/secrule/paged-search'
        
        logging.debug(f"Searching rules with query: {query}")
        return self._paged_get(f"{url}?q={query}&sort=policy.name&sort=order")
    
    def get_device(self, domain_id: int, device_id: int) -> Dict[str, Any]:
        """
        Get details for a specific device.
        
        Args:
            domain_id: Domain ID
            device_id: Device ID
            
        Returns:
            Device dictionary
        """
        url = f'{self.api_url}/domain/{domain_id}/device/{device_id}'
        return self._get(url)
    
    def update_rule_doc(self, domain_id: int, device_id: int,
                       rule_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update a rule document (props).

        Args:
            domain_id: Domain ID
            device_id: Device ID
            rule_doc: Rule document with props to update (must include 'ruleId')

        Returns:
            Response dictionary
        """
        url = f'{self.api_url}/domain/{domain_id}/device/{device_id}/ruledoc'
        return self._put(url, rule_doc)


# ============================================================================
# RULE MATCHER
# ============================================================================

class RuleMatcher:
    """Matches rules between management stations and child devices based on rule definitions."""
    
    def __init__(self):
        """Initialize the rule matcher."""
        self.logger = logging.getLogger(__name__)
    
    def match_rules(self, mgmt_rules: List[Dict[str, Any]], 
                   child_rules: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """
        Match management station rules to child device rules.
        
        Args:
            mgmt_rules: List of rules from management station
            child_rules: List of rules from child device
            
        Returns:
            List of tuples (mgmt_rule, child_rule) for matched pairs
        """
        matches = []
        matched_child_ids = set()
        
        for mgmt_rule in mgmt_rules:
            # Try to find a matching rule in child device
            match = self._find_matching_rule(mgmt_rule, child_rules, matched_child_ids)
            
            if match:
                matches.append((mgmt_rule, match))
                matched_child_ids.add(match['matchId'])
                
                self.logger.debug(
                    f"Matched: '{mgmt_rule.get('displayName')}' -> '{match.get('displayName')}'"
                )
            else:
                self.logger.debug(
                    f"No match found for management rule: '{mgmt_rule.get('displayName')}'"
                )
        
        return matches
    
    def _find_matching_rule(self, mgmt_rule: Dict[str, Any], 
                           child_rules: List[Dict[str, Any]],
                           matched_ids: Set[str]) -> Optional[Dict[str, Any]]:
        """
        Find a matching rule in child device rules.
        
        Args:
            mgmt_rule: Rule from management station
            child_rules: List of rules from child device
            matched_ids: Set of already matched child rule IDs
            
        Returns:
            Matching child rule or None
        """
        for child_rule in child_rules:
            # Skip already matched rules
            if child_rule['matchId'] in matched_ids:
                continue
            
            # Check if rules match
            if self._rules_match(mgmt_rule, child_rule):
                return child_rule
        
        return None
    
    def _rules_match(self, rule1: Dict[str, Any], rule2: Dict[str, Any]) -> bool:
        """
        Check if two rules match based on their definitions.
        
        Rules match if they have the same:
        - Rule name
        - Policy name
        - Action
        - Sources
        - Destinations
        - Services
        - Direction
        
        Args:
            rule1: First rule to compare
            rule2: Second rule to compare
            
        Returns:
            True if rules match, False otherwise
        """
        # Check rule name
        if not self._compare_strings(rule1.get('ruleName'), rule2.get('ruleName')):
            return False
        
        # Check policy name
        policy1 = rule1.get('policy', {}).get('name', '')
        policy2 = rule2.get('policy', {}).get('name', '')
        if not self._compare_strings(policy1, policy2):
            return False
        
        # Check rule action
        if rule1.get('ruleAction') != rule2.get('ruleAction'):
            return False
        
        # Check direction
        if rule1.get('direction') != rule2.get('direction'):
            return False
        
        # Check sources
        if not self._compare_network_objects(rule1.get('sources', []), rule2.get('sources', [])):
            return False
        
        # Check destinations
        if not self._compare_network_objects(rule1.get('destinations', []), rule2.get('destinations', [])):
            return False
        
        # Check services
        if not self._compare_service_objects(rule1.get('services', []), rule2.get('services', [])):
            return False
        
        # Check source zones
        src_zones1 = rule1.get('srcContext', {}).get('zones', [])
        src_zones2 = rule2.get('srcContext', {}).get('zones', [])
        if not self._compare_zones(src_zones1, src_zones2):
            return False
        
        # Check destination zones
        dst_zones1 = rule1.get('dstContext', {}).get('zones', [])
        dst_zones2 = rule2.get('dstContext', {}).get('zones', [])
        if not self._compare_zones(dst_zones1, dst_zones2):
            return False
        
        return True
    
    def _compare_strings(self, str1: Optional[str], str2: Optional[str]) -> bool:
        """Compare two strings, handling None values."""
        if str1 is None and str2 is None:
            return True
        if str1 is None or str2 is None:
            return False
        return str1.strip() == str2.strip()
    
    def _compare_network_objects(self, objs1: List[Dict[str, Any]], 
                                 objs2: List[Dict[str, Any]]) -> bool:
        """
        Compare two lists of network objects.
        
        Network objects match if they have the same names or addresses.
        """
        if len(objs1) != len(objs2):
            return False
        
        # Extract comparable data from objects
        set1 = self._extract_network_object_keys(objs1)
        set2 = self._extract_network_object_keys(objs2)
        
        return set1 == set2
    
    def _extract_network_object_keys(self, objs: List[Dict[str, Any]]) -> Set[str]:
        """Extract unique identifiers from network objects."""
        keys = set()
        
        for obj in objs:
            # Use display name as primary key
            name = obj.get('displayName', obj.get('name', ''))
            
            # For ANY objects, use special marker
            if obj.get('type') == 'ANY':
                keys.add('__ANY__')
                continue
            
            # Clean the name (remove scope suffix like ":Shared")
            clean_name = name.split(':')[0].strip() if ':' in name else name
            
            # For FQDN objects, use FQDN
            if obj.get('networkType') == 'FQDN' or obj.get('fqdn'):
                fqdn = obj.get('fqdn', clean_name)
                keys.add(f"FQDN:{fqdn}")
                continue
            
            # For objects with addresses, use addresses
            addresses = obj.get('addresses', [])
            if addresses:
                for addr in addresses:
                    addr_str = addr.get('address', '')
                    if addr_str:
                        keys.add(f"ADDR:{addr_str}")
            else:
                # Fall back to name
                keys.add(f"NAME:{clean_name}")
        
        return keys
    
    def _compare_service_objects(self, objs1: List[Dict[str, Any]], 
                                objs2: List[Dict[str, Any]]) -> bool:
        """
        Compare two lists of service objects.
        """
        if len(objs1) != len(objs2):
            return False
        
        set1 = self._extract_service_object_keys(objs1)
        set2 = self._extract_service_object_keys(objs2)
        
        return set1 == set2
    
    def _extract_service_object_keys(self, objs: List[Dict[str, Any]]) -> Set[str]:
        """Extract unique identifiers from service objects."""
        keys = set()
        
        for obj in objs:
            # For ANY objects
            if obj.get('type') == 'ANY':
                keys.add('__ANY__')
                continue
            
            # Get display name
            name = obj.get('displayName', obj.get('name', ''))
            clean_name = name.split(':')[0].strip() if ':' in name else name
            
            # For objects with actual service definitions
            services = obj.get('services', [])
            if services:
                for svc in services:
                    svc_str = svc.get('formattedValue', '')
                    if svc_str:
                        keys.add(f"SVC:{svc_str}")
            else:
                # Use name for application-default and similar
                keys.add(f"NAME:{clean_name}")
        
        return keys
    
    def _compare_zones(self, zones1: List[Dict[str, Any]], 
                      zones2: List[Dict[str, Any]]) -> bool:
        """Compare two lists of zones."""
        if len(zones1) != len(zones2):
            return False
        
        set1 = self._extract_zone_keys(zones1)
        set2 = self._extract_zone_keys(zones2)
        
        return set1 == set2
    
    def _extract_zone_keys(self, zones: List[Dict[str, Any]]) -> Set[str]:
        """Extract unique identifiers from zones."""
        keys = set()
        
        for zone in zones:
            if zone.get('type') == 'ANY':
                keys.add('__ANY__')
            else:
                name = zone.get('displayName', zone.get('name', ''))
                keys.add(name.strip())
        
        return keys


# ============================================================================
# MAIN SYNC LOGIC
# ============================================================================

class RuleDocSyncer:
    """Main class for syncing rule documentation from management stations to child devices."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None
        self.matcher = RuleMatcher()
        self.custom_props_cache = None
        
    def initialize(self) -> bool:
        """Initialize the syncer with API connection."""
        try:
            setup_logging(
                self.config['log_filename'],
                self.config['log_level'],
                self.config['log_max_bytes'],
                self.config['log_backup_count']
            )

            # Initialize API client
            self.client = FireMonClient(
                self.config['url'],
                self.config['user'],
                self.config['password'],
                self.config['page_size'],
                self.config['verify_ssl']
            )

            # Load custom properties for prop conversion
            self._load_custom_properties()

            logging.info("Initialization successful")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize: {e}")
            return False

    def _load_custom_properties(self) -> None:
        """Load custom rule properties from API."""
        try:
            url = f'{self.client.api_url}/customproperty/domain/{self.config["domain_id"]}?disabled=false'
            response = self.client._get(url)

            # Handle both list and dict responses
            if isinstance(response, list):
                self.custom_props_cache = response
            elif isinstance(response, dict) and 'results' in response:
                self.custom_props_cache = response['results']
            else:
                self.custom_props_cache = []

            logging.info(f"Loaded {len(self.custom_props_cache)} custom properties")

        except Exception as e:
            logging.warning(f"Failed to load custom properties: {e}")
            self.custom_props_cache = []

    def _convert_props_dict_to_list(self, props_dict: Dict[str, Any], rule_id: str) -> List[Dict[str, Any]]:
        """Convert props dictionary to list format expected by API."""
        if not self.custom_props_cache:
            logging.error("No custom properties loaded - cannot convert props")
            return []

        props_list = []

        for key, value in props_dict.items():
            # Find matching custom property definition
            prop_def = None
            for prop in self.custom_props_cache:
                if prop.get('key') == key:
                    prop_def = prop
                    break

            if not prop_def:
                logging.warning(f"No custom property definition found for key: {key}")
                continue

            # Build property object matching import_ruledoc.py format (lines 654-678)
            prop_obj = {
                'ruleId': rule_id,
                'ruleCustomPropertyDefinition': {
                    'id': prop_def.get('ruleCustomPropertyDefinitionId', prop_def.get('id')),
                    'customPropertyDefinition': {
                        'id': prop_def['id'],
                        'name': prop_def['name'],
                        'key': prop_def['key'],
                        'type': prop_def['type'],
                        'filterable': prop_def.get('filterable', False)
                    },
                    'type': prop_def['type'],
                    'key': prop_def['key'],
                    'name': prop_def['name']
                },
                'customProperty': {
                    'id': prop_def['id'],
                    'name': prop_def['name'],
                    'key': prop_def['key'],
                    'type': prop_def['type'],
                    'filterable': prop_def.get('filterable', False)
                }
            }

            # Set value based on type
            prop_type = prop_def['type']
            if prop_type == 'STRING':
                prop_obj['stringval'] = str(value)
            elif prop_type == 'STRING_ARRAY':
                prop_obj['stringarray'] = [str(value)] if not isinstance(value, list) else value
            elif prop_type == 'INTEGER':
                prop_obj['intval'] = int(value)
            elif prop_type == 'LONG':
                prop_obj['longval'] = int(value)
            elif prop_type == 'DOUBLE':
                prop_obj['doubleval'] = float(value)
            elif prop_type == 'BOOLEAN':
                prop_obj['boolval'] = bool(value)
            elif prop_type == 'DATE':
                prop_obj['dateval'] = str(value)
            else:
                prop_obj['stringval'] = str(value)

            props_list.append(prop_obj)

        return props_list
    
    def get_management_stations(self) -> List[Dict[str, Any]]:
        """Get all management stations in the domain."""
        logging.info("Fetching management stations...")
        
        query = f"domain {{ id = {self.config['domain_id']} }} AND device {{ type = 'DEVICE_MGR' }}"
        mgmt_stations = self.client.search_devices(query)
        
        logging.info(f"Found {len(mgmt_stations)} management station(s)")
        for station in mgmt_stations:
            logging.info(f"  - {station['name']} (ID: {station['id']}, Product: {station.get('product', 'Unknown')})")
        
        return mgmt_stations
    
    def get_child_devices(self, mgmt_station_id: int) -> List[Dict[str, Any]]:
        """Get all child devices for a management station."""
        logging.info(f"Fetching child devices for management station {mgmt_station_id}...")
        
        query = f"device{{managementstationid={mgmt_station_id}}}"
        child_devices = self.client.search_devices(query)
        
        logging.info(f"Found {len(child_devices)} child device(s)")
        for device in child_devices:
            logging.info(f"  - {device['name']} (ID: {device['id']}, Type: {device.get('deviceType', 'Unknown')})")
        
        return child_devices
    
    def get_rules_with_props(self, device_id: int, device_name: str) -> List[Dict[str, Any]]:
        """Get all rules with their props for a device."""
        logging.info(f"Fetching rules for device '{device_name}' (ID: {device_id})...")
        
        # Query includes props field to get custom properties
        query = f"device{{id={device_id}}} | fields(tfacount, props, controlstat, usage(date('last 30 days')), change, highlight)"
        
        try:
            rules = self.client.search_rules(query)
            logging.info(f"Found {len(rules)} rule(s) on device '{device_name}'")
            
            # Count rules with props
            rules_with_props = sum(1 for rule in rules if rule.get('props'))
            logging.info(f"  {rules_with_props} rule(s) have custom properties")
            
            return rules
        except Exception as e:
            logging.error(f"Error fetching rules for device {device_id}: {e}")
            return []
    
    def sync_management_station(self, mgmt_station: Dict[str, Any]) -> Dict[str, int]:
        """Sync rules from a management station to its child devices."""
        mgmt_id = mgmt_station['id']
        mgmt_name = mgmt_station['name']
        
        logging.info("="*80)
        logging.info(f"Syncing Management Station: {mgmt_name} (ID: {mgmt_id})")
        logging.info("="*80)
        
        stats = {
            'child_devices': 0,
            'rules_matched': 0,
            'rules_updated': 0,
            'rules_failed': 0,
            'rules_no_match': 0
        }
        
        # Get management station rules
        mgmt_rules = self.get_rules_with_props(mgmt_id, mgmt_name)
        if not mgmt_rules:
            logging.warning(f"No rules found on management station {mgmt_name}")
            return stats
        
        # Filter to only rules with props
        mgmt_rules_with_props = [r for r in mgmt_rules if r.get('props')]
        if not mgmt_rules_with_props:
            logging.warning(f"No rules with custom properties found on management station {mgmt_name}")
            return stats
        
        logging.info(f"Processing {len(mgmt_rules_with_props)} management station rules with props")
        
        # Get child devices
        child_devices = self.get_child_devices(mgmt_id)
        if not child_devices:
            logging.warning(f"No child devices found for management station {mgmt_name}")
            return stats
        
        stats['child_devices'] = len(child_devices)
        
        # Process each child device
        for child_device in child_devices:
            child_stats = self.sync_child_device(mgmt_rules_with_props, child_device)
            stats['rules_matched'] += child_stats['matched']
            stats['rules_updated'] += child_stats['updated']
            stats['rules_failed'] += child_stats['failed']
            stats['rules_no_match'] += child_stats['no_match']
        
        return stats
    
    def sync_child_device(self, mgmt_rules: List[Dict[str, Any]], 
                         child_device: Dict[str, Any]) -> Dict[str, int]:
        """Sync rules from management station to a single child device."""
        child_id = child_device['id']
        child_name = child_device['name']
        
        logging.info(f"\nSyncing to child device: {child_name} (ID: {child_id})")
        
        stats = {
            'matched': 0,
            'updated': 0,
            'failed': 0,
            'no_match': 0
        }
        
        # Get child device rules
        child_rules = self.get_rules_with_props(child_id, child_name)
        if not child_rules:
            logging.warning(f"No rules found on child device {child_name}")
            return stats
        
        # Match rules between management station and child device
        matches = self.matcher.match_rules(mgmt_rules, child_rules)
        stats['matched'] = len(matches)
        
        logging.info(f"Matched {len(matches)} rules between management station and child device")
        
        # Sync props for each matched rule
        for mgmt_rule, child_rule in matches:
            if self.sync_single_rule(mgmt_rule, child_rule, child_id, child_name):
                stats['updated'] += 1
            else:
                stats['failed'] += 1
        
        # Count unmatched management rules for this device
        matched_mgmt_ids = {mgmt_rule['matchId'] for mgmt_rule, _ in matches}
        stats['no_match'] = len(mgmt_rules) - len(matched_mgmt_ids)
        
        if stats['no_match'] > 0:
            logging.info(f"{stats['no_match']} management station rules had no match on child device")
        
        return stats
    
    def sync_single_rule(self, mgmt_rule: Dict[str, Any], child_rule: Dict[str, Any],
                        child_device_id: int, child_device_name: str) -> bool:
        """Sync props from a management station rule to a child device rule."""
        mgmt_props_raw = mgmt_rule.get('props')
        child_props_raw = child_rule.get('props')

        # Handle empty props
        if not mgmt_props_raw:
            logging.debug(f"No props to sync for rule '{child_rule.get('displayName')}'")
            return True

        # Convert props dict to list format if necessary
        if isinstance(mgmt_props_raw, dict):
            logging.debug(f"Converting props dict to list format for rule '{child_rule.get('displayName')}'")
            mgmt_props = self._convert_props_dict_to_list(mgmt_props_raw, child_rule['matchId'])
        elif isinstance(mgmt_props_raw, list):
            mgmt_props = mgmt_props_raw
        else:
            logging.error(f"Props is not a dict or list: {type(mgmt_props_raw)}")
            return False

        if not mgmt_props:
            logging.debug(f"No valid props after conversion for rule '{child_rule.get('displayName')}'")
            return True

        # For comparison, also convert child props if needed
        if isinstance(child_props_raw, dict):
            child_props = self._convert_props_dict_to_list(child_props_raw, child_rule['matchId'])
        elif isinstance(child_props_raw, list):
            child_props = child_props_raw if child_props_raw else []
        else:
            child_props = []

        # Check if props are different (simple length check for now)
        if mgmt_props == child_props:
            logging.debug(f"Props already in sync for rule '{child_rule.get('displayName')}' on {child_device_name}")
            return True

        # Build rule doc for update - match the format from import_ruledoc.py
        rule_doc = {
            'ruleId': child_rule['matchId'],
            'deviceId': child_device_id,
            'createDate': None,
            'lastUpdated': None,
            'lastRevisionDate': None,
            'props': mgmt_props,
            'expirationDate': None
        }

        try:
            logging.info(f"Updating rule '{child_rule.get('displayName')}' on {child_device_name}")
            logging.debug(f"  Management station props: {mgmt_props}")
            logging.debug(f"  Child device props (before): {child_props}")

            self.client.update_rule_doc(
                self.config['domain_id'],
                child_device_id,
                rule_doc
            )

            logging.info(f"  Successfully synced props")
            return True

        except requests.exceptions.HTTPError as e:
            error_msg = f"  Failed to sync props: {e}"
            if hasattr(e, 'response') and e.response is not None:
                error_msg += f"\n  Response: {e.response.text}"
            logging.error(error_msg)
            return False
        except Exception as e:
            logging.error(f"  Failed to sync props: {e}")
            return False
    
    def run(self, mgmt_station_id: Optional[int] = None) -> int:
        """Main execution method."""
        if not self.initialize():
            return 1
        
        try:
            # Get management stations to sync
            if mgmt_station_id:
                # Sync specific management station
                logging.info(f"Syncing specific management station ID: {mgmt_station_id}")
                mgmt_stations = [{'id': mgmt_station_id, 'name': f'Management Station {mgmt_station_id}'}]
            else:
                # Get all management stations
                mgmt_stations = self.get_management_stations()
                if not mgmt_stations:
                    logging.warning("No management stations found")
                    return 0
            
            # Process each management station
            total_stats = {
                'mgmt_stations': len(mgmt_stations),
                'child_devices': 0,
                'rules_matched': 0,
                'rules_updated': 0,
                'rules_failed': 0,
                'rules_no_match': 0
            }
            
            for mgmt_station in mgmt_stations:
                stats = self.sync_management_station(mgmt_station)
                total_stats['child_devices'] += stats['child_devices']
                total_stats['rules_matched'] += stats['rules_matched']
                total_stats['rules_updated'] += stats['rules_updated']
                total_stats['rules_failed'] += stats['rules_failed']
                total_stats['rules_no_match'] += stats['rules_no_match']
            
            # Print summary to both console and log
            summary = [
                "",
                "="*80,
                "Sync Summary:",
                "="*80,
                f"Management stations processed: {total_stats['mgmt_stations']}",
                f"Child devices processed: {total_stats['child_devices']}",
                f"Rules matched: {total_stats['rules_matched']}",
                f"Rules updated: {total_stats['rules_updated']}",
                f"Rules failed: {total_stats['rules_failed']}",
                f"Rules with no match: {total_stats['rules_no_match']}",
                "="*80
            ]

            # Print to console
            for line in summary:
                print(line)

            # Also log it
            logging.info("\n".join(summary))

            return 0 if total_stats['rules_failed'] == 0 else 1
            
        except Exception as e:
            logging.error(f"Error during sync: {e}", exc_info=True)
            return 1


# ============================================================================
# TEST CONNECTION
# ============================================================================

def test_connection(config: Dict[str, Any]) -> bool:
    """Test connection to FireMon Security Manager."""
    print("\n" + "="*80)
    print("FireMon Connection Test")
    print("="*80)
    
    print("\nConfiguration:")
    print(f"  URL: {config['url']}")
    print(f"  User: {config['user']}")
    print(f"  Password: {'*' * len(config['password'])}")
    print(f"  Domain ID: {config['domain_id']}")
    
    print("\nTesting API connection and authentication...")
    try:
        client = FireMonClient(
            config['url'],
            config['user'],
            config['password'],
            config['page_size'],
            config['verify_ssl']
        )
        print("  Connected and authenticated")
    except Exception as e:
        print(f"  Failed: {e}")
        return False
    
    print("\nTesting management station retrieval...")
    try:
        query = f"domain {{ id = {config['domain_id']} }} AND device {{ type = 'DEVICE_MGR' }}"
        mgmt_stations = client.search_devices(query)
        print(f"  Found {len(mgmt_stations)} management station(s)")
        
        for station in mgmt_stations[:5]:
            print(f"     - {station.get('name')} (ID: {station.get('id')})")
        if len(mgmt_stations) > 5:
            print(f"     ... and {len(mgmt_stations) - 5} more")
    except Exception as e:
        print(f"  Failed: {e}")
        return False
    
    print("\n" + "="*80)
    print("All tests passed! Ready to sync.")
    print("="*80)
    return True


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='FireMon Rule Documentation Sync Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  FIREMON_URL          FireMon server URL
  FIREMON_USER         Username
  FIREMON_PASSWORD     Password
  FIREMON_DOMAIN_ID    Domain ID (default: 1)
  FIREMON_LOG_FILE     Log file path (default: ./sync_ruledoc_log.txt)
  FIREMON_LOG_LEVEL    Log level (DEBUG, INFO, WARNING, ERROR)
  FIREMON_PAGE_SIZE    API page size (default: 100)
  FIREMON_VERIFY_SSL   Verify SSL certificates (true/false, default: false)

Examples:
  # Test connection
  python3 sync_ruledoc.py --test
  
  # Sync all management stations
  python3 sync_ruledoc.py
  
  # Sync specific management station
  python3 sync_ruledoc.py --mgmt-id 1289
        """
    )
    
    parser.add_argument(
        '--mgmt-id',
        type=int,
        help='Sync specific management station ID'
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test connection and configuration'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Initialize FireMon environment
    print("Initializing FireMon environment...")
    if not initialize_firemon_environment():
        sys.exit(1)
    
    # Load configuration
    config = load_config()
    
    if args.debug:
        config['log_level'] = logging.DEBUG
    
    if args.test:
        success = test_connection(config)
        sys.exit(0 if success else 1)
    else:
        syncer = RuleDocSyncer(config)
        sys.exit(syncer.run(args.mgmt_id))


if __name__ == "__main__":
    main()