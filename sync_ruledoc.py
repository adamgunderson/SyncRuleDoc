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
    # Configure root logger
    root_logger = logging.getLogger()

    # Clear any existing handlers to prevent duplicates
    root_logger.handlers.clear()

    root_logger.setLevel(log_level)

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
    
    def get_rule_doc(self, domain_id: int, device_id: int, rule_id: str) -> Dict[str, Any]:
        """
        Get a rule document (props) - returns current/actual props, not cached SIQL data.

        Args:
            domain_id: Domain ID
            device_id: Device ID
            rule_id: Rule ID (matchId)

        Returns:
            Rule document dictionary
        """
        url = f'{self.api_url}/domain/{domain_id}/device/{device_id}/rule/{rule_id}/ruledoc'
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
        mgmt_display = mgmt_rule.get('displayName', mgmt_rule.get('ruleName', 'Unknown'))

        for child_rule in child_rules:
            # Skip already matched rules
            if child_rule['matchId'] in matched_ids:
                continue

            child_display = child_rule.get('displayName', child_rule.get('ruleName', 'Unknown'))
            self.logger.debug(f"Comparing mgmt '{mgmt_display}' with child '{child_display}'")

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

        Args:
            rule1: First rule to compare
            rule2: Second rule to compare

        Returns:
            True if rules match, False otherwise
        """
        # Check rule name
        if not self._compare_strings(rule1.get('ruleName'), rule2.get('ruleName')):
            self.logger.debug(f"  Rule name mismatch: '{rule1.get('ruleName')}' vs '{rule2.get('ruleName')}'")
            return False

        # Check policy name - SKIPPED due to FireMon bug in policy name filter
        # policy1 = rule1.get('policy', {}).get('name', '')
        # policy2 = rule2.get('policy', {}).get('name', '')
        # if not self._compare_strings(policy1, policy2):
        #     self.logger.debug(f"  Policy name mismatch: '{policy1}' vs '{policy2}'")
        #     return False

        # Check rule action
        if rule1.get('ruleAction') != rule2.get('ruleAction'):
            self.logger.debug(f"  Action mismatch: '{rule1.get('ruleAction')}' vs '{rule2.get('ruleAction')}'")
            return False

        # Check sources
        if not self._compare_network_objects(rule1.get('sources', []), rule2.get('sources', [])):
            self.logger.debug(f"  Source mismatch")
            return False

        # Check destinations
        if not self._compare_network_objects(rule1.get('destinations', []), rule2.get('destinations', [])):
            self.logger.debug(f"  Destination mismatch")
            return False

        # Check services
        if not self._compare_service_objects(rule1.get('services', []), rule2.get('services', [])):
            self.logger.debug(f"  Service mismatch")
            return False

        # Check source zones
        src_zones1 = rule1.get('srcContext', {}).get('zones', [])
        src_zones2 = rule2.get('srcContext', {}).get('zones', [])
        if not self._compare_zones(src_zones1, src_zones2):
            self.logger.debug(f"  Source zone mismatch")
            return False

        # Check destination zones
        dst_zones1 = rule1.get('dstContext', {}).get('zones', [])
        dst_zones2 = rule2.get('dstContext', {}).get('zones', [])
        if not self._compare_zones(dst_zones1, dst_zones2):
            self.logger.debug(f"  Destination zone mismatch")
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
            # API field names: stringval, integerval, booleanval, dateval, stringarray, usernameval
            prop_type = prop_def['type']
            if prop_type == 'STRING':
                prop_obj['stringval'] = str(value)
            elif prop_type == 'STRING_ARRAY':
                # Handle different formats for string arrays
                if isinstance(value, list):
                    prop_obj['stringarray'] = value
                elif isinstance(value, str):
                    # Check if it's in the format "{item1, item2}" or "{item1}"
                    if value.startswith('{') and value.endswith('}'):
                        # Remove curly braces and split by comma
                        inner_value = value[1:-1].strip()
                        if inner_value:
                            prop_obj['stringarray'] = [s.strip() for s in inner_value.split(',')]
                        else:
                            prop_obj['stringarray'] = []
                    else:
                        # Just a plain string, wrap in array
                        prop_obj['stringarray'] = [value]
                else:
                    prop_obj['stringarray'] = [str(value)]
            elif prop_type == 'INTEGER':
                prop_obj['integerval'] = int(value)
            elif prop_type == 'LONG':
                prop_obj['integerval'] = int(value)  # LONG also uses integerval
            elif prop_type == 'BOOLEAN':
                prop_obj['booleanval'] = bool(value)
            elif prop_type == 'DATE':
                # The API expects ISO 8601 format: YYYY-MM-DDTHH:mm:ss±HHMM
                # Example: "2025-10-10T00:00:00-0700"
                prop_obj['dateval'] = self._format_date_iso8601(str(value))
            else:
                # Unknown type - log warning and use string value
                logging.warning(f"Unknown property type '{prop_type}' for key '{key}', using stringval")
                prop_obj['stringval'] = str(value)

            props_list.append(prop_obj)

        return props_list

    def _merge_props_for_sync(self, props_dict: Dict[str, Any], all_props_list: List[Dict[str, Any]],
                              rule_id: str) -> List[Dict[str, Any]]:
        """
        Merge property values with the full list of properties.

        This creates a list of ALL properties in the system, with values from props_dict
        where available, and without value fields (cleared) where not available.

        Args:
            props_dict: Dictionary of property key -> value (from SIQL dict format)
            all_props_list: List of all property definitions (from child device ruledoc API)
            rule_id: Rule ID for the props

        Returns:
            List of property objects in API format
        """
        if not all_props_list:
            # No properties defined in system, convert props_dict to list
            if not props_dict:
                return []
            return self._convert_props_dict_to_list(props_dict, rule_id)

        merged_props = []

        for prop_def in all_props_list:
            # Get the property key
            prop_key = prop_def.get('ruleCustomPropertyDefinition', {}).get('key') or \
                      prop_def.get('customProperty', {}).get('key')

            if not prop_key:
                continue

            # Check if this property has a value in props_dict
            if prop_key in props_dict and props_dict[prop_key] is not None:
                # Property has a value in the dict (simple value like string, date, etc.)
                # Convert it to full property object format
                single_prop_dict = {prop_key: props_dict[prop_key]}
                converted = self._convert_props_dict_to_list(single_prop_dict, rule_id)
                if converted:
                    merged_props.extend(converted)
            else:
                # Property doesn't have a value, add definition without value field
                empty_prop = {
                    'ruleId': rule_id,
                    'ruleCustomPropertyDefinition': prop_def.get('ruleCustomPropertyDefinition'),
                    'customProperty': prop_def.get('customProperty')
                }
                merged_props.append(empty_prop)

        return merged_props

    def _create_empty_props_list(self, child_props_raw: Any, rule_id: str) -> List[Dict[str, Any]]:
        """
        Create a list of props with empty values to clear properties on child device.

        The FireMon API doesn't support sending an empty array to clear all props.
        Instead, we need to send the property definitions with empty/null values.

        Args:
            child_props_raw: Current props from child device (dict or list)
            rule_id: Rule ID for the props

        Returns:
            List of property objects with empty values
        """
        if not child_props_raw:
            # Child has no props, return empty list
            return []

        # Convert child props to list format if needed
        if isinstance(child_props_raw, dict):
            child_props = self._convert_props_dict_to_list(child_props_raw, rule_id)
        elif isinstance(child_props_raw, list):
            child_props = child_props_raw
        else:
            return []

        # Create props with empty values
        # Note: To clear a property value, we OMIT the value field entirely (don't set to null or empty string)
        empty_props = []
        for prop in child_props:
            # Create a clean copy with only the structure, no value fields
            empty_prop = {
                'ruleId': rule_id,
                'ruleCustomPropertyDefinition': prop.get('ruleCustomPropertyDefinition'),
                'customProperty': prop.get('customProperty')
            }

            # Explicitly remove all value fields to clear the property
            # Do NOT include: stringval, stringarray, integerval, booleanval, dateval, usernameval

            empty_props.append(empty_prop)

        return empty_props

    def _create_rule_match_key(self, rule: Dict[str, Any]) -> tuple:
        """
        Create a composite key for matching rules based on multiple attributes.
        Uses rule name, policy name, action, source zones, destination zones, and services.

        Args:
            rule: Rule dictionary

        Returns:
            Tuple containing (rule_name, policy_name, action, src_zones, dst_zones, services)
        """
        rule_name = rule.get('displayName', '')
        policy_name = rule.get('policy', {}).get('displayName', '')
        action = rule.get('action', '')

        # Extract source zone names (sorted for consistent matching)
        src_zones = []
        sources = rule.get('sources', {})
        if isinstance(sources, dict):
            zone_list = sources.get('zone', [])
        else:
            # sources might be a list directly
            zone_list = sources if isinstance(sources, list) else []

        for zone in zone_list:
            if isinstance(zone, dict) and zone.get('type') != 'ANY':
                zone_name = zone.get('displayName') or zone.get('name', '')
                if zone_name:
                    src_zones.append(zone_name)
        src_zones_tuple = tuple(sorted(src_zones))

        # Extract destination zone names (sorted for consistent matching)
        dst_zones = []
        destinations = rule.get('destinations', {})
        if isinstance(destinations, dict):
            zone_list = destinations.get('zone', [])
        else:
            # destinations might be a list directly
            zone_list = destinations if isinstance(destinations, list) else []

        for zone in zone_list:
            if isinstance(zone, dict) and zone.get('type') != 'ANY':
                zone_name = zone.get('displayName') or zone.get('name', '')
                if zone_name:
                    dst_zones.append(zone_name)
        dst_zones_tuple = tuple(sorted(dst_zones))

        # Extract service names (sorted for consistent matching)
        services_list = []
        services = rule.get('services', {})
        if isinstance(services, dict):
            svc_list = services.get('service', [])
        else:
            # services might be a list directly
            svc_list = services if isinstance(services, list) else []

        for svc in svc_list:
            if isinstance(svc, dict) and svc.get('type') != 'ANY':
                svc_name = svc.get('displayName') or svc.get('name', '')
                if svc_name:
                    services_list.append(svc_name)
        services_tuple = tuple(sorted(services_list))

        return (rule_name, policy_name, action, src_zones_tuple, dst_zones_tuple, services_tuple)

    def _format_date_iso8601(self, date_str: str) -> str:
        """
        Convert a date string to ISO 8601 format with timezone (no microseconds).

        Args:
            date_str: Date string in various formats (e.g., "2022-03-12 00:00:00" or "2025-09-09T17:50:54.191446")

        Returns:
            ISO 8601 formatted string (e.g., "2022-03-12T00:00:00-0700")
        """
        from datetime import datetime
        import time
        import re

        # If already in correct format, return as-is
        if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}$', date_str):
            return date_str

        try:
            # Strip microseconds if present (e.g., ".191446")
            working_str = re.sub(r'\.\d+', '', date_str)

            # Strip any existing timezone info to parse the base datetime
            clean_str = working_str
            # Remove timezone patterns: +HHMM, -HHMM, +HH:MM, -HH:MM, Z
            clean_str = re.sub(r'[+-]\d{2}:?\d{2}$', '', clean_str)
            clean_str = clean_str.rstrip('Z')

            # Parse the date string - try common formats
            date_obj = None
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                try:
                    date_obj = datetime.strptime(clean_str, fmt)
                    break
                except ValueError:
                    continue

            if not date_obj:
                raise ValueError(f"Unable to parse date: {date_str}")

            # Get local timezone offset
            if time.daylight:
                offset_sec = -time.altzone
            else:
                offset_sec = -time.timezone

            offset_hours = offset_sec // 3600
            offset_minutes = (abs(offset_sec) % 3600) // 60
            offset_sign = '+' if offset_sec >= 0 else '-'

            # Format as YYYY-MM-DDTHH:mm:ss±HHMM (no microseconds)
            formatted = date_obj.strftime('%Y-%m-%dT%H:%M:%S')
            formatted += f"{offset_sign}{abs(offset_hours):02d}{offset_minutes:02d}"

            return formatted

        except Exception as e:
            logging.error(f"Failed to parse date: {date_str}, Error: {e}")
            raise ValueError(f"Cannot format date '{date_str}' to ISO 8601 format")

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
        query = f"device{{id={device_id}}} | fields(props)"

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

    def find_matching_rule_by_siql(self, mgmt_rule: Dict[str, Any], child_device_id: int) -> Optional[Dict[str, Any]]:
        """
        Find a matching rule on the child device using SIQL query.

        Args:
            mgmt_rule: Rule from management station
            child_device_id: Child device ID to search

        Returns:
            Matching child rule or None
        """
        # Build SIQL query to match the management station rule
        # Note: Due to FireMon bug, we can't use device ID and policy.name in same query
        # So we use policy stanza separately and filter by child device ID after

        rule_name = mgmt_rule.get('ruleName', '')
        if not rule_name:
            logging.debug("Management rule has no ruleName, cannot search by SIQL")
            return None

        # Escape single quotes in rule name for SIQL
        escaped_name = rule_name.replace("'", "\\'")

        # Build the query components - start with rule stanza
        # All rule filters (name, action, zones) must be in the same stanza
        rule_conditions = [f"ruleName='{escaped_name}'"]

        # Add action filter (action field is supported)
        if mgmt_rule.get('ruleAction'):
            rule_conditions.append(f"action='{mgmt_rule['ruleAction']}'")

        # Add zone filters to rule stanza
        src_zones = mgmt_rule.get('srcContext', {}).get('zones', [])
        dst_zones = mgmt_rule.get('dstContext', {}).get('zones', [])

        # Build source zone filter (OR conditions for multiple zones)
        src_zone_names = [z.get('displayName', z.get('name', '')) for z in src_zones
                         if z.get('type') != 'ANY' and (z.get('displayName') or z.get('name'))]
        if src_zone_names:
            if len(src_zone_names) == 1:
                escaped_zone = src_zone_names[0].replace("'", "\\'")
                rule_conditions.append(f"(source.zone = '{escaped_zone}')")
            else:
                # Multiple zones - use OR
                zone_conditions = [f"source.zone = '{z.replace(chr(39), chr(92)+chr(39))}'" for z in src_zone_names]
                rule_conditions.append(f"({' OR '.join(zone_conditions)})")

        # Build destination zone filter (OR conditions for multiple zones)
        dst_zone_names = [z.get('displayName', z.get('name', '')) for z in dst_zones
                         if z.get('type') != 'ANY' and (z.get('displayName') or z.get('name'))]
        if dst_zone_names:
            if len(dst_zone_names) == 1:
                escaped_zone = dst_zone_names[0].replace("'", "\\'")
                rule_conditions.append(f"(destination.zone = '{escaped_zone}')")
            else:
                # Multiple zones - use OR
                zone_conditions = [f"destination.zone = '{z.replace(chr(39), chr(92)+chr(39))}'" for z in dst_zone_names]
                rule_conditions.append(f"({' OR '.join(zone_conditions)})")

        # Build complete rule stanza
        query_parts = [f"rule {{ {' AND '.join(rule_conditions)} }}"]

        # Add policy stanza separately (can't be combined with device ID due to FireMon bug)
        policy_name = mgmt_rule.get('policy', {}).get('name')
        if policy_name:
            escaped_policy = policy_name.replace("'", "\\'")
            query_parts.append(f" AND policy {{ displayName = '{escaped_policy}' }}")

        # Add fields to retrieve props
        query_parts.append(" | fields(props)")

        query = "".join(query_parts)

        logging.debug(f"SIQL query for rule matching: {query}")

        try:
            results = self.client.search_rules(query)

            if not results:
                logging.debug(f"No SIQL match found for rule '{rule_name}'")
                return None

            # Filter results by child device ID (since we can't include it in the query)
            # Note: Device ID is in ndDevice.id, not deviceId
            filtered_results = [r for r in results if r.get('ndDevice', {}).get('id') == child_device_id]

            if not filtered_results:
                logging.debug(f"Found rules with name '{rule_name}' but none on device {child_device_id}")
                return None

            if len(filtered_results) > 1:
                logging.warning(f"Multiple SIQL matches found for rule '{rule_name}' on device {child_device_id}, using first match")

            return filtered_results[0]

        except Exception as e:
            logging.debug(f"SIQL search failed for rule '{rule_name}': {e}")
            return None
    
    def sync_management_station(self, mgmt_station: Dict[str, Any]) -> Dict[str, int]:
        """Sync rules from a management station to its child devices."""
        mgmt_id = mgmt_station['id']

        # Fetch full device details to get the actual device name
        try:
            device_details = self.client.get_device(self.config['domain_id'], mgmt_id)
            # Try to get the best name available
            mgmt_name = device_details.get('description') or device_details.get('name') or f"Management Station {mgmt_id}"
        except Exception as e:
            logging.debug(f"Could not fetch device details for ID {mgmt_id}: {e}")
            mgmt_name = mgmt_station.get('name', f"Management Station {mgmt_id}")

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
        
        # Get management station rules (includes rules with props and without)
        mgmt_rules = self.get_rules_with_props(mgmt_id, mgmt_name)
        if not mgmt_rules:
            logging.warning(f"No rules found on management station {mgmt_name}")
            return stats

        # Note: We process all rules (even those without props on mgmt station)
        # because child devices might have props that need to be cleared
        # The sync_single_rule method will check if sync is needed
        logging.info(f"Processing {len(mgmt_rules)} management station rules")
        
        # Get child devices
        child_devices = self.get_child_devices(mgmt_id)
        if not child_devices:
            logging.warning(f"No child devices found for management station {mgmt_name}")
            return stats
        
        stats['child_devices'] = len(child_devices)
        
        # Process each child device
        for child_device in child_devices:
            child_stats = self.sync_child_device(mgmt_rules, child_device)
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

        # Fetch ALL child device rules once (much more efficient than per-rule queries)
        logging.debug(f"Fetching all rules for child device {child_id}")
        child_rules = self.get_rules_with_props(child_id, child_name)

        if not child_rules:
            logging.warning(f"No rules found on child device {child_name}")
            return stats

        logging.debug(f"Found {len(child_rules)} rules on child device")

        # Build lookup dict for fast matching using composite key
        # Key includes: rule_name, policy_name, action, source_zones, dest_zones, services
        child_rules_lookup = {}
        for child_rule in child_rules:
            key = self._create_rule_match_key(child_rule)
            # If duplicate keys exist, log warning but keep first match
            if key in child_rules_lookup:
                rule_name = child_rule.get('displayName', '')
                policy_name = child_rule.get('policy', {}).get('displayName', '')
                logging.warning(f"Duplicate rule found on child: '{rule_name}' in policy '{policy_name}'")
            else:
                child_rules_lookup[key] = child_rule

        # Match management rules to child rules
        for mgmt_rule in mgmt_rules:
            mgmt_rule_name = mgmt_rule.get('displayName', '')
            mgmt_policy_name = mgmt_rule.get('policy', {}).get('displayName', '')

            if not mgmt_rule_name or not mgmt_policy_name:
                logging.debug(f"Skipping rule without name or policy")
                continue

            # Look up matching child rule using composite key
            key = self._create_rule_match_key(mgmt_rule)
            child_rule = child_rules_lookup.get(key)

            if child_rule:
                stats['matched'] += 1
                if self.sync_single_rule(mgmt_rule, child_rule, child_id, child_name):
                    stats['updated'] += 1
                else:
                    stats['failed'] += 1
            else:
                stats['no_match'] += 1
                logging.debug(f"No match found for management rule: '{mgmt_rule_name}' in policy '{mgmt_policy_name}'")

        logging.info(f"Matched {stats['matched']} rules, updated {stats['updated']}, failed {stats['failed']}, no match {stats['no_match']}")

        return stats
    
    def sync_single_rule(self, mgmt_rule: Dict[str, Any], child_rule: Dict[str, Any],
                        child_device_id: int, child_device_name: str) -> bool:
        """Sync props from a management station rule to a child device rule."""

        # Get the management station device ID from the rule
        mgmt_device_id = mgmt_rule.get('ndDevice', {}).get('id')

        # Fetch ACTUAL current props from ruledoc API (not cached SIQL data)
        # This ensures we're comparing current state, not stale SIQL cache
        try:
            mgmt_ruledoc = self.client.get_rule_doc(
                self.config['domain_id'],
                mgmt_device_id,
                mgmt_rule['matchId']
            )
            mgmt_props_raw = mgmt_ruledoc.get('props')
        except Exception as e:
            logging.warning(f"Could not fetch mgmt station ruledoc, using SIQL data: {e}")
            mgmt_props_raw = mgmt_rule.get('props')

        try:
            child_ruledoc = self.client.get_rule_doc(
                self.config['domain_id'],
                child_device_id,
                child_rule['matchId']
            )
            child_props_raw = child_ruledoc.get('props')
        except Exception as e:
            logging.warning(f"Could not fetch child ruledoc, using SIQL data: {e}")
            child_props_raw = child_rule.get('props')

        # Quick check: if both have no props (empty list or None), skip
        if not mgmt_props_raw and not child_props_raw:
            logging.debug(f"Both management and child have no props, skipping '{child_rule.get('displayName')}'")
            return True

        # Convert management station props to list format
        if not mgmt_props_raw:
            # Management station has no props - need to clear all child props
            # We'll handle this by creating a merged list with all props cleared
            mgmt_props_dict = {}
        elif isinstance(mgmt_props_raw, dict):
            logging.debug(f"Converting props dict to list format for rule '{child_rule.get('displayName')}'")
            mgmt_props_dict = mgmt_props_raw
        elif isinstance(mgmt_props_raw, list):
            # Convert list (from ruledoc API) to dict for easier merging
            # Extract actual values from property objects
            mgmt_props_dict = {}
            for prop in mgmt_props_raw:
                # Get the key from the property definition
                key = prop.get('ruleCustomPropertyDefinition', {}).get('key') or \
                      prop.get('customProperty', {}).get('key')
                if key:
                    # Extract the actual value based on the value field present
                    if 'stringval' in prop:
                        mgmt_props_dict[key] = prop['stringval']
                    elif 'stringarray' in prop:
                        mgmt_props_dict[key] = prop['stringarray']
                    elif 'integerval' in prop:
                        mgmt_props_dict[key] = prop['integerval']
                    elif 'booleanval' in prop:
                        mgmt_props_dict[key] = prop['booleanval']
                    elif 'dateval' in prop:
                        mgmt_props_dict[key] = prop['dateval']
                    elif 'usernameval' in prop:
                        mgmt_props_dict[key] = prop['usernameval']
                    # If no value field present, the property is cleared - don't add to dict
        else:
            logging.error(f"Props is not a dict or list: {type(mgmt_props_raw)}")
            return False

        # Get child props in list format for merging
        if isinstance(child_props_raw, dict):
            child_props_list = self._convert_props_dict_to_list(child_props_raw, child_rule['matchId'])
        elif isinstance(child_props_raw, list):
            child_props_list = child_props_raw
        else:
            child_props_list = []

        # Build the merged props list to send to API
        # We need to send ALL properties that exist in the system, with values from mgmt station
        mgmt_props = self._merge_props_for_sync(mgmt_props_dict, child_props_list, child_rule['matchId'])

        # For comparison, convert child props to same format
        if isinstance(child_props_raw, dict):
            child_props_dict_for_compare = child_props_raw
        elif isinstance(child_props_raw, list):
            # Extract values from list format
            child_props_dict_for_compare = {}
            for prop in child_props_raw:
                key = prop.get('ruleCustomPropertyDefinition', {}).get('key') or \
                      prop.get('customProperty', {}).get('key')
                if key:
                    # Extract the actual value
                    if 'stringval' in prop:
                        child_props_dict_for_compare[key] = prop['stringval']
                    elif 'stringarray' in prop:
                        child_props_dict_for_compare[key] = prop['stringarray']
                    elif 'integerval' in prop:
                        child_props_dict_for_compare[key] = prop['integerval']
                    elif 'booleanval' in prop:
                        child_props_dict_for_compare[key] = prop['booleanval']
                    elif 'dateval' in prop:
                        child_props_dict_for_compare[key] = prop['dateval']
                    elif 'usernameval' in prop:
                        child_props_dict_for_compare[key] = prop['usernameval']
        else:
            child_props_dict_for_compare = {}

        child_props = self._merge_props_for_sync(
            child_props_dict_for_compare,
            child_props_list,
            child_rule['matchId']
        )

        # Check if props are different
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
            
            # Print summary
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

            # Log it (will appear in both console and file due to handlers)
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