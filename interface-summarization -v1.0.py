#!/usr/bin/env python3

import requests
import json
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as ET
import xml.dom.minidom
from tabulate import tabulate
from datetime import datetime
import sys
import getpass
import re
import argparse
import time

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

class ACIInterfaceInfo:
    def __init__(self, apic_url, username, password):
        """Initialize connection to APIC
        Args:
            apic_url (str): APIC URL (e.g., https://apic)
            username (str): APIC username
            password (str): APIC password
        """
        self.apic_url = apic_url.rstrip('/')  # Remove trailing slash if present
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.refresh_timeout = None
        self.token = None
        self.interfaces = []
        self.debug = False  # Initialize debug flag
        
    def set_debug(self, enabled=True):
        """Enable or disable debug output"""
        self.debug = enabled
    
    def debug_print(self, *args, **kwargs):
        """Print only if debug is enabled"""
        if self.debug:
            print(*args, **kwargs)

    def _refresh_token(self):
        """Refresh the authentication token before timeout"""
        if not self.token or not self.refresh_timeout:
            return self.login()
            
        current_time = time.time()
        if current_time >= self.refresh_timeout - 60:  # Refresh 60 seconds before timeout
            self.debug_print("Token about to expire, refreshing...")
            return self.login()
        return True

    def list_auth_domains(self):
        """Get available authentication domains from APIC"""
        domains_url = f"{self.apic_url}/api/aaaListDomains.json"
        try:
            print(f"\nGetting authentication domains from: {domains_url}")
            response = self.session.get(
                domains_url,
                timeout=10
            )
            
            print(f"Response status code: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                domains = []
                for domain in data.get('imdata', []):
                    if isinstance(domain, dict):
                        # Each domain has name and type directly in the imdata array
                        name = domain.get('name', '')
                        domain_type = domain.get('type', '')
                        if name:
                            domains.append({'name': name, 'type': domain_type})
                return domains
            else:
                print(f"Error getting domains. Status code: {response.status_code}")
                print(f"Error Content: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Failed to get authentication domains: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error while getting domains: {str(e)}")
            return None

    def login(self, selected_domain="DefaultAuth"):
        """Login to APIC and get token"""
        try:
            # Format username with domain
            if selected_domain == "DefaultAuth":
                domain_username = self.username  # Don't add domain prefix for DefaultAuth
            else:
                domain_username = f"apic:{selected_domain}\\{self.username}"
            print(f"\nLogging in with username: {domain_username}")
            
            login_url = f"{self.apic_url}/api/aaaLogin.json"
            payload = {
                "aaaUser": {
                    "attributes": {
                        "name": domain_username,
                        "pwd": self.password
                    }
                }
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                login_url,
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data['imdata'][0]['aaaLogin']['attributes']['token']
                timeout = int(data['imdata'][0]['aaaLogin']['attributes'].get('refreshTimeoutSeconds', '600'))
                
                self.token = token
                self.refresh_timeout = time.time() + timeout
                self.session.headers.update({
                    'APIC-Cookie': token
                })
                print("Successfully logged in to APIC")
                return True
            else:
                if response.text:
                    error_data = response.json()
                    error_message = error_data.get('imdata', [{}])[0].get('error', {}).get('attributes', {}).get('text', 'Unknown error')
                    print(f"Login failed: {error_message}")
                else:
                    print(f"Login failed with status code: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Network error during login: {str(e)}")
            return False
        except Exception as e:
            print(f"Unexpected error during login: {str(e)}")
            return False

    def _make_request(self, method, url, **kwargs):
        """Make a request to APIC with automatic token refresh"""
        # Try to refresh token if needed
        if not self._refresh_token():
            return None
            
        try:
            response = self.session.request(method, url, **kwargs)
            if response.status_code == 403:  # Token might have expired
                self.debug_print("Got 403, trying to refresh token...")
                if self._refresh_token():  # Try refresh and retry request
                    response = self.session.request(method, url, **kwargs)
            return response
        except Exception as e:
            print(f"Error making request: {str(e)}")
            return None

    def get_interface_info(self):
        """Get interface information using l1PhysIf class"""
        query_url = f"{self.apic_url}/api/node/class/l1PhysIf.json"
        query_params = {
            'order-by': 'l1PhysIf.modTs|desc'
        }
        
        response = self._make_request('GET', query_url, params=query_params)
        if response and response.status_code == 200:
            return response.json()
        else:
            self.debug_print(f"Error Content: {response.text if response else 'No response'}")
            return None

    def get_transceiver_info(self):
        """Get transceiver information using ethpmFcot class"""
        query_url = f"{self.apic_url}/api/node/class/ethpmFcot.json"
        query_params = {
            'order-by': 'ethpmFcot.modTs|desc'
        }
        
        response = self._make_request('GET', query_url, params=query_params)
        if response and response.status_code == 200:
            return response.json()
        else:
            self.debug_print(f"Error Content: {response.text if response else 'No response'}")
            return None

    def get_interface_faults(self):
        """Get interface faults"""
        query_url = f"{self.apic_url}/api/node/class/faultInst.json?query-target-filter=and(wcard(faultInst.cause,\"interface\"))"
        query_params = {
            'order-by': 'faultInst.modTs|desc'
        }
        
        response = self._make_request('GET', query_url, params=query_params)
        if response and response.status_code == 200:
            return response.json()
        else:
            self.debug_print(f"Error Content: {response.text if response else 'No response'}")
            return None

    def get_transceiver_dn(self, interface_dn):
        """Convert interface DN to transceiver DN format"""
        # Example interface DN: topology/pod-1/node-101/sys/phys-[eth1/1]
        # Example transceiver DN: topology/pod-1/node-101/sys/phys-[eth1/1]/phys/fcot
        return f"{interface_dn}/phys/fcot"

    def parse_dn(self, dn):
        """Parse DN string to extract pod, node, and interface
        Examples:
        - Ethernet: topology/pod-1/node-101/sys/phys-[eth1/1]
        - Port-channel: topology/pod-1/node-101/sys/aggr-[po10]
        - Loopback: topology/pod-1/node-101/sys/lb-[lo10]
        - FEX: topology/pod-1/node-101/sys/phys-[eth101/1/1]
        """
        pod = node = interface = None
        
        # Extract pod number
        pod_match = re.search(r'pod-(\d+)', dn)
        if pod_match:
            pod = pod_match.group(1)
            
        # Extract node number
        node_match = re.search(r'node-(\d+)', dn)
        if node_match:
            node = node_match.group(1)
            
        # Extract interface name
        # Try ethernet interface first (including FEX)
        eth_match = re.search(r'phys-\[(?:eth)?(\d+(?:/\d+){1,2})\]', dn)
        if eth_match:
            interface = f"eth{eth_match.group(1)}"
        else:
            # Try port-channel
            po_match = re.search(r'aggr-\[(?:po)?(\d+)\]', dn)
            if po_match:
                interface = f"po{po_match.group(1)}"
            else:
                # Try loopback
                lo_match = re.search(r'lb-\[(?:lo)?(\d+)\]', dn)
                if lo_match:
                    interface = f"lo{lo_match.group(1)}"
                
        self.debug_print(f"Parsed DN: pod={pod}, node={node}, interface={interface}")
        return pod, node, interface

    def get_physical_details(self, dn):
        """Get physical interface details including operational state and reason."""
        # Example input DN: topology/pod-1/node-101/sys/phys-[eth1/14]
        # We need: topology/pod-1/node-101/sys/phys-[eth1/14]/phys
        
        # Check if DN is in correct format
        if not dn or '/phys-[' not in dn:
            print(f"Invalid DN format for physical details: {dn}")
            return {'operSt': 'down', 'operStQual': '', 'lastLinkStChg': ''}
            
        # Ensure DN doesn't already have /phys at the end
        if dn.endswith('/phys'):
            phys_dn = dn
        else:
            phys_dn = f"{dn}/phys"
        
        url = f"{self.apic_url}/api/mo/{phys_dn}.json"
        try:
            response = self._make_request('GET', url)
            response.raise_for_status()
            data = response.json()
            
            if data.get('imdata'):
                phys_if = data['imdata'][0].get('ethpmPhysIf', {}).get('attributes', {})
                return {
                    'operSt': phys_if.get('operSt', 'down').lower(),
                    'operStQual': phys_if.get('operStQual', ''),
                    'lastLinkStChg': phys_if.get('lastLinkStChg', '')
                }
            else:
                print(f"No physical interface data found for {phys_dn}")
        except Exception as e:
            print(f"Error getting physical details for {phys_dn}: {str(e)}")
        
        return {'operSt': 'down', 'operStQual': '', 'lastLinkStChg': ''}

    def to_xml(self):
        """Convert interface information to XML format"""
        root = ET.Element("InterfaceInformation")
        root.set("timestamp", datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
        
        for interface in self.interfaces:
            if_elem = ET.SubElement(root, "Interface")
            ET.SubElement(if_elem, "Node").text = interface.get('node', '')
            ET.SubElement(if_elem, "Name").text = interface.get('interface', '')
            ET.SubElement(if_elem, "Description").text = interface.get('description', '')
            ET.SubElement(if_elem, "AdminState").text = interface.get('adminSt', '')
            ET.SubElement(if_elem, "SwitchingState").text = interface.get('switchingSt', '')
            ET.SubElement(if_elem, "OperState").text = interface.get('operSt', '')
            ET.SubElement(if_elem, "OperReason").text = interface.get('operStQual', '')
            ET.SubElement(if_elem, "LastStateChange").text = interface.get('lastLinkStChg', '')
            ET.SubElement(if_elem, "Speed").text = interface.get('speed', '')
            ET.SubElement(if_elem, "Layer").text = interface.get('layer', '')
            ET.SubElement(if_elem, "Usage").text = interface.get('usage', '')
            ET.SubElement(if_elem, "MTU").text = interface.get('mtu', '')
            
            # Add transceiver information
            transceiver = ET.SubElement(if_elem, "Transceiver")
            ET.SubElement(transceiver, "Type").text = interface.get('transceiver', {}).get('type', '')
            ET.SubElement(transceiver, "Serial").text = interface.get('transceiver', {}).get('serial', '')
            ET.SubElement(transceiver, "Vendor").text = interface.get('transceiver', {}).get('vendor', '')
        
        return root

    def save_interface_info(self, filename):
        """Save interface and transceiver information to XML file"""
        interface_data = self.get_interface_info()
        transceiver_data = self.get_transceiver_info()
        fault_data = self.get_interface_faults()
        
        if not interface_data:
            print("\nNo interface data received from API")
            return

        # Create lookup for transceivers by DN
        transceiver_lookup = {}
        for item in transceiver_data.get('imdata', []):
            if 'ethpmFcot' in item:
                fcot = item['ethpmFcot']['attributes']
                dn = fcot.get('dn', '')
                # Get the interface DN part (remove /phys/fcot)
                interface_dn = '/'.join(dn.split('/')[:-2])
                transceiver_lookup[interface_dn] = fcot

        # Create lookup for faults by DN
        fault_lookup = {}
        if fault_data:
            for item in fault_data.get('imdata', []):
                if 'faultInst' in item:
                    fault = item['faultInst']['attributes']
                    dn = fault.get('dn', '')
                    # Extract interface DN from fault DN
                    if '/phys-[' in dn:
                        interface_dn = dn.split('/fault-')[0]
                        if interface_dn not in fault_lookup:
                            fault_lookup[interface_dn] = []
                        fault_lookup[interface_dn].append(fault)

        # Get current timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_filename = f"{filename}_{timestamp}.xml"
        
        # Initialize table headers and data
        headers = ["Node", "Interface", "Description", "Admin State", "Switching State", "Oper State", "Oper Reason", "Speed", "Layer", "Usage", "MTU", "Type", "Serial", "Vendor"]
        table_data = []
        
        if interface_data.get('imdata'):
            print(f"\nFound {len(interface_data['imdata'])} interface entries")
            for item in interface_data['imdata']:
                if 'l1PhysIf' in item:
                    l1if = item['l1PhysIf']['attributes']
                    dn = l1if.get('dn', '')
                    
                    # Get physical interface details
                    phys_details = self.get_physical_details(dn)
                    
                    # Get transceiver info for this interface
                    transceiver = transceiver_lookup.get(dn, {})
                    
                    # Parse DN for pod/node/interface
                    pod, node, interface = self.parse_dn(dn)
                    
                    # Skip if not a physical interface
                    if not interface or not interface.startswith('eth'):
                        continue
                        
                    # Get admin and switching states
                    admin_state = l1if.get('adminSt', 'down').lower()
                    switching_state = l1if.get('switchingSt', 'disabled').lower()
                    
                    # Ensure admin state is only 'up' or 'down'
                    admin_state = 'up' if admin_state == 'up' else 'down'

                    # Add additional state info if operationally down
                    if phys_details['operSt'] == 'down':
                        print(f"\nInterface {interface} on Node-{node} is operationally down:")
                        print(f"  Operational State: {phys_details['operSt']}")
                        print(f"  Reason: {phys_details['operStQual']}")
                        print(f"  Last State Change: {phys_details['lastLinkStChg']}")
                    
                    # Create interface info
                    interface_info = {
                        'pod': f"Pod-{pod}" if pod else "N/A",
                        'node': f"Node-{node}" if node else "N/A",
                        'interface': interface if interface else "N/A",
                        'description': l1if.get('descr', 'N/A'),
                        'adminSt': admin_state,
                        'switchingSt': switching_state,
                        'operSt': phys_details['operSt'],
                        'operStQual': phys_details['operStQual'],
                        'lastLinkStChg': phys_details['lastLinkStChg'],
                        'speed': l1if.get('speed', 'N/A'),
                        'layer': l1if.get('layer', 'N/A'),
                        'usage': l1if.get('usage', 'N/A'),
                        'mtu': l1if.get('mtu', 'N/A'),
                        'transceiver': {
                            'type': transceiver.get('typeName', ''),
                            'serial': transceiver.get('guiSN', ''),
                            'vendor': transceiver.get('guiName', '')
                        }
                    }
                    self.interfaces.append(interface_info)
                    
                    # Add to table data
                    table_data.append([
                        f"Node-{node}" if node else "N/A",
                        interface if interface else "N/A",
                        l1if.get('descr', 'N/A'),
                        admin_state,
                        switching_state,
                        phys_details['operSt'],
                        phys_details['operStQual'],
                        l1if.get('speed', 'N/A'),
                        l1if.get('layer', 'N/A'),
                        l1if.get('usage', 'N/A'),
                        l1if.get('mtu', 'N/A'),
                        transceiver.get('typeName', ''),
                        transceiver.get('guiSN', ''),
                        transceiver.get('guiName', '')
                    ])
        
        # Sort table data by node and interface
        table_data.sort(key=lambda x: (x[0], x[1]))
        
        # Save to XML file with pretty printing
        try:
            xml_str = ET.tostring(self.to_xml(), encoding='unicode')
            pretty_xml = xml.dom.minidom.parseString(xml_str).toprettyxml()
            
            with open(xml_filename, 'w') as f:
                f.write(pretty_xml)
            
            print(f"\nSaved interface information to {xml_filename}")
            
            # Display summary table
            print("\nInterface Summary:")
            print(tabulate(table_data, headers=headers, tablefmt="pretty", numalign="left", stralign="left"))
            
        except Exception as e:
            print(f"Failed to save XML file: {str(e)}")

def get_credentials():
    """Prompt for APIC credentials"""
    print("\nEnter APIC connection details:")
    while True:
        apic = input("APIC IP/hostname [https://172.24.207.2]: ").strip()
        if not apic:
            apic = "https://172.24.207.2"
        
        # Ensure URL starts with https://
        if not apic.startswith("https://"):
            apic = f"https://{apic}"

        # Create temporary instance to get auth domains
        temp_aci = ACIInterfaceInfo(apic, "", "")
        print("\nRetrieving authentication domains...")
        domains = temp_aci.list_auth_domains()
        
        if domains:
            print("\nAvailable authentication domains:")
            for i, domain in enumerate(domains, 1):
                print(f"{i}. {domain['name']} ({domain['type']})")
            
            while True:
                try:
                    choice = int(input("\nSelect authentication domain (1-{}): ".format(len(domains))))
                    if 1 <= choice <= len(domains):
                        selected_domain = domains[choice-1]['name']
                        break
                    else:
                        print("Invalid choice. Please try again.")
                except ValueError:
                    print("Please enter a number.")
        else:
            print("Could not retrieve authentication domains. Using default authentication.")
            selected_domain = "DefaultAuth"

        max_attempts = 3
        for attempt in range(max_attempts):
            username = input("Username [admin]: ").strip()
            if not username:
                username = "admin"
                
            password = getpass.getpass("Password: ")
            if not password:
                print("Password cannot be empty. Please try again.")
                continue

            # Create a test instance to verify credentials
            test_aci = ACIInterfaceInfo(apic, username, password)
            if test_aci.login(selected_domain):
                return apic, selected_domain, username, password
            
            attempts_left = max_attempts - attempt - 1
            if attempts_left > 0:
                print(f"\nLogin failed. {attempts_left} attempts remaining. Please try again.")
            else:
                print("\nMaximum login attempts exceeded. Exiting.")
                sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Get ACI interface information')
    parser.add_argument('-a', '--apic', help='APIC IP/hostname (e.g., https://172.24.207.2)')
    parser.add_argument('-u', '--username', help='APIC username')
    parser.add_argument('-p', '--password', help='APIC password')
    parser.add_argument('-f', '--filename', default='interface_info', help='Base filename for output (default: interface_info)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    # Get credentials either from arguments or prompt
    if args.apic and args.username and args.password:
        apic_url = args.apic
        username = args.username
        password = args.password
        selected_domain = "DefaultAuth"  # Use default for command line args
    else:
        apic_url, selected_domain, username, password = get_credentials()

    # Initialize ACI interface info
    aci = ACIInterfaceInfo(apic_url, username, password)
    
    # Enable debug if requested
    if args.debug:
        aci.set_debug(True)
    
    # Login to APIC with selected domain
    if not aci.login(selected_domain):
        print("Failed to login to APIC")
        return
    
    # Save interface info
    aci.save_interface_info(args.filename)

if __name__ == "__main__":
    main()
