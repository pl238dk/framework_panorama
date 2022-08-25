import json
import requests
requests.packages.urllib3.disable_warnings()
from getpass import getpass
import xml.etree.ElementTree as xml

class PAN(object):
	version = '9.0'
	def __init__(self,hostname):
		self.hostname = hostname
		self.base_url = f'https://{hostname}/url/{self.version}/'
		self.session = requests.Session()
		self.token = ''
		return

	def authenticate(self,username,password=''):
		url = f'{self.hostname}/api/?type=keygenauth'
		data = {
			'type':	'keygen',
			'user':     username,
			'password':     '',
		}
		if password:
			data['password'] = password
		else:
			data['password'] = getpass('Password: ')
		response = self.session.get(url, params=data, verify=False)
		if response.status_code == 200:
			print('[I] Logon successful')
			et_raw = xml.fromstring(response.text)
			token = et_raw[0][0].text
			headers = {
				'X-PAN-KEY':	token,
			}
			self.session.headers.update(headers)
		else:
			print('[E] Login failed')
		return
	
	def get(self, path, params={}):
		url = f'{self.base_url}{path}'
		response_raw = self.session.get(url, params=params, verify=False)
		if response_raw.status_code == 200:
			#result = self.parse_xml(response_raw)
			result = json.loads(response_raw.text)
			return {
				'success':	True,
				'result':	result,
				'response_object':	response_raw,
			}
		else:
			return {
				'success':	False,
				'result':	'',
				'response_object':	response_raw,
			}
		return
	
	# OBJECTS
	
	def get_object_addresses(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/Addresses', params=_params)
		return output
	
	def get_object_address_groups(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/AddressesGroups', params=_params)
		return output
	
	def get_object_regions(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/Regions', params=_params)
		return output
	
	def get_object_applications(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/Applications', params=_params)
		return output
	
	def get_object_application_groups(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/ApplicationGroups', params=_params)
		return output
	
	def get_object_application_filters(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/ApplicationFilters', params=_params)
		return output
	
	def get_object_services(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/Services', params=_params)
		return output
	
	def get_object_service_groups(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/ServiceGroups', params=_params)
		return output
	
	def get_object_tags(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/Tags', params=_params)
		return output
	
	def get_object_global_protect_hip_objects(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/GlobalProtectHIPObjects', params=_params)
		return output
	
	def get_object_global_protect_hip_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/GlobalProtectHIPProfiles', params=_params)
		return output
	
	def get_object_external_dynamic_lists(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/ExternalDynamicLists', params=_params)
		return output
	
	def get_object_custom_data_patterns(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/CustomDataPatterns', params=_params)
		return output
	
	def get_object_custom_spyware_signatures(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/CustomSpywareSignatures', params=_params)
		return output
	
	def get_object_custom_vulnerability_signatures(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/CustomVulnerabilitySignatures', params=_params)
		return output
	
	def get_object_custom_url_categories(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/CustomURLCategories', params=_params)
		return output
	
	def get_object_antivirus_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/AntivirusSecurityProfiles', params=_params)
		return output
	
	def get_object_antispyware_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/AntiSpywareSecurityProfiles', params=_params)
		return output
	
	def get_object_vulnerability_protection_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/VulnerabilityProtectionSecurityProfiles', params=_params)
		return output
	
	def get_object_url_filtering_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/URLFilteringSecurityProfiles', params=_params)
		return output
	
	def get_object_file_blocking_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/FileBlockingSecurityProfiles', params=_params)
		return output
	
	def get_object_wildfire_analysis_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/WildFireAnalysisSecurityProfiles', params=_params)
		return output
	
	def get_object_data_filtering_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/DataFilteringSecurityProfiles', params=_params)
		return output
	
	def get_object_dos_protection_security_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/DoSProtectionSecurityProfiles', params=_params)
		return output
	
	def get_object_security_profile_groups(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/SecurityProfileGroups', params=_params)
		return output
	
	def get_object_log_forwarding_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/LogForwardingProfiles', params=_params)
		return output
	
	def get_object_authentication_enforcements(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/AuthenticationEnforcements', params=_params)
		return output
	
	def get_object_decryption_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/DecryptionProfiles', params=_params)
		return output
	
	def get_object_decryption_forwarding_profiles(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/DecryptionForwardingProfiles', params=_params)
		return output
	
	def get_object_schedules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Objects/Schedules', params=_params)
		return output
	
	# POLICIES
	
	def get_policy_security_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/SecurityRules', params=_params)
		return output
	
	def get_policy_nat_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/NATRules', params=_params)
		return output
	
	def get_policy_qos_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/QoSRules', params=_params)
		return output
	
	def get_policy_policy_based_forwarding_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/PolicyBasedForwardingRules', params=_params)
		return output
	
	def get_policy_decryption_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/DecryptionRules', params=_params)
		return output
	
	def get_policy_tunnel_inspection_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/TunnelInspectionRules', params=_params)
		return output
	
	def get_policy_application_override_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/ApplicationOverrideRules', params=_params)
		return output
	
	def get_policy_authentication_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/AuthenticationRules', params=_params)
		return output
	
	def get_policy_dos_rules(self):
		_params = {
			'location':	'vsys',
			'vsys':	'vsys1',
		}
		output = self.get('Policies/DoSRules', params=_params)
		return output
	
	def parse_xml(self, xml_raw):
		output = []
		et_raw = xml.fromstring(xml_raw.text)
		entries = list(et_raw[-1])
		if not entries:
			print('[E] nothing to parse')
			return ''
		for entry in list(entries):
			if not entry:
				continue
			else:
				info = {}
			for attribute in list(entry):
				if len(list(attribute)) > 0:
					info[attribute.tag] = {}
					for attribute_child in list(attribute):
						info[attribute.tag][attribute_child.tag] = attribute_child.text
				else:
					info[attribute.tag] = attribute.text
			output.append(info)
		return output

if __name__ == '__main__':
	host = 'pan01.domain.com'
	un = ''
	p = PAN(host)
	p.authenticate(un)
	print('\n','[I] List of Objects')
	r = p.get_object_addresses()
	for x in r['result']['result']['entry']: print(x)
	#
	print('\n','[I] List of Policies')
	r = p.get_policy_security_rules()
	for x in r['result']['result']['entry']: print(x)