import requests
import time
import base64
import logging
import os
import debugpy
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from ldap3 import Server, Connection, ALL, NTLM

# Configure logging
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
numeric_level = getattr(logging, log_level, None)
if not isinstance(numeric_level, int):
	raise ValueError(f'Invalid log level: {log_level}')
logging.basicConfig(level=numeric_level, format='%(asctime)s - %(levelname)s - %(message)s')


""" List of all department ids in the JSS """

departments = {
	'-1': 'No Department',
	'5': 'Y7',
	'6': 'Y8',
	'7': 'Y9',
	'8': 'Y10',
	'9': 'Y11',
	'10': 'Y12',
	'11': 'Staff',
	'12': 'Y6',
	'13': 'Y5',
	'14': 'Y4',
	'15': 'Y3',
	'16': 'Y2',
	'17': 'Y1',
	'18': 'Y0',
	'19': 'ELC',
	'20': 'Y13',
	'21': 'IT',
	'22': 'Testing',
	'23': 'IWBs',
	'24': 'Spares',
	'25': 'NA',
	'26': 'Disabled'
}

""" List of all building ids in the JSS """

buildings = {
	'-1': 'No Building',
	'1': 'Senior Campus',
	'2': 'Penbank',
	'3': 'Minimbah',
	'4': 'Disabled'
}

class Device:
	def __init__(self, id, deviceType, name, jamfUser, ldapUser=None):
		self.id = id
		self.deviceType = deviceType
		self.name = name
		self.jamfUser = jamfUser
	
	def needsToUpdate(self):
		return self.jamfUser != self.ldapUser
	
class User:
	def __init__(self, username, buildingID=None, departmentID=None, real_name=None, email=None, disabled=False):
		if disabled:
			self.building = '4'
			self.department = '26'
		else:
			if buildingID in buildings.keys():
				self.building = buildingID
			else:
				self.building = -1
			
			if departmentID in departments.keys():
				self.department = departmentID
			else:
				self.department = -1
		self.username = username
		self.real_name = real_name
		self.email = email
		self.disabled = disabled
	
	def __eq__(self, other):
		if isinstance(other, User):
			if self.building == other.building and\
				self.department == other.department and\
				self.username == other.username and\
				self.real_name == other.real_name and\
				self.email == other.email:
				return True
			else:
				return False

class UpdateUserInfo:
	def __init__(self, host, jamf_client_id, jamf_client_secret, ldap_host, ldap_username, ldap_credentials):
		self.jamf_host = host
		self.jamf_client_id = jamf_client_id
		self.jamf_client_secret = jamf_client_secret
		self.ldap_host = ldap_host
		self.ldap_username = ldap_username
		self.ldap_credentials = ldap_credentials
		self.__connnect_to_ldap__()
		self.__authenticate_jamf_api__()
		logging.info('Initialized service')

	def __authenticate_jamf_api__(self):
		logging.debug('Authenticating to Jamf API...')
		headers = {'Content-Type': 'application/x-www-form-urlencoded'}
		data = {
			'client_id': self.jamf_client_id,
			'client_secret': self.jamf_client_secret,
			'grant_type': 'client_credentials'
		}
		response = requests.post(f'https://{self.jamf_host}/api/oauth/token', headers=headers, data=data)
		response.raise_for_status()
		self.jamf_access_token = response.json()['access_token']
		self.jamf_token_expiry = datetime.now(timezone.utc) + timedelta(seconds=response.json()['expires_in'])
		logging.debug('Successfully retrieved an access token')

	def __check_token__(self):
		logging.debug('Checking access token expiry...')
		if datetime.now(timezone.utc) >= self.jamf_token_expiry:
			logging.info('Access token expired, re-authenticating...')
			self.__authenticate_jamf_api__()
		else:
			logging.debug('Access token fine')

	def __connnect_to_ldap__(self):
		logging.debug('Binding to LDAP')
		server = Server(self.ldap_host, get_info=ALL)
		self.ldap_connection = Connection(server, user=self.ldap_username, password=base64.b64decode(self.ldap_credentials).decode('utf-8'), client_strategy='RESTARTABLE', auto_bind=True)
		self.ldap_connection.bind()
		logging.debug('Successfully bound to LDAP')

	def getAllMacDevices(self):
		self.__check_token__()
		
		logging.debug('Getting all macOS devices')
		devices = []
		
		headers = {
			'Accept': 'application/json',
			'Authorization': f'Bearer {self.jamf_access_token}'
		}

		query = {
			'section': [
				'GENERAL',
				'USER_AND_LOCATION'
			],
			'page-size': 5000,
			'filter': 'general.remoteManagement.managed==true'
		}

		response = requests.get(f'https://{self.jamf_host}/api/v1/computers-inventory', params=query, headers=headers)
		response.raise_for_status()

		for deviceDetails in response.json()['results']:
			userDetails = deviceDetails['userAndLocation']
			if userDetails['username'] != None:
				user = User(userDetails['username'],
							userDetails['buildingId'],
							userDetails['departmentId'],
							userDetails['realname'],
							userDetails['email'],
				)
				device = Device(deviceDetails['id'],'macOS', deviceDetails['general']['name'], user)
				try:
					self.getLDAPDetails(device)
					devices.append(device)
				except IndexError:
					logging.error(f'No information found for {device.jamfUser.username}')
			else:
				logging.info(f'No user associated with {deviceDetails["general"]["name"]}, skipping over...')
				continue
		return devices

	def getAlliOSDevices(self):
		self.__check_token__()
		
		logging.info('Getting all iOS devices...')
		devices = []

		headers = {
			'Accept': 'application/json',
			'Authorization': f'Bearer {self.jamf_access_token}'
		}

		query = {
			'section': [
				'GENERAL',
				'USER_AND_LOCATION'
			],
			'page-size': 5000,
			'filter': 'managed==true'
		}

		response = requests.get(f'https://{self.jamf_host}/api/v2/mobile-devices/detail', params=query, headers=headers)
		response.raise_for_status()

		for deviceDetails in response.json()['results']:
			userDetails = deviceDetails['userAndLocation']
			if userDetails['username'] != '':
				user = User(userDetails['username'],
							userDetails['buildingId'],
							userDetails['departmentId'],
							userDetails['realName'],
							userDetails['emailAddress']
				)
				device = Device(deviceDetails['mobileDeviceId'], 'iOS', deviceDetails['general']['displayName'], user)
				try:
					self.getLDAPDetails(device)
					devices.append(device)
				except IndexError:
					logging.error(f'No information found for {device.jamfUser.username}')
			else:
				logging.info(f'No user associated with {deviceDetails["general"]["displayName"]}, skipping over...')
				continue

		return devices

	def updateUser(self, device):
		self.__check_token__()

		try:
			building = buildings[device.ldapUser.building]
		except KeyError:
			building = 'No building'
		
		try:
			department = departments[device.ldapUser.department]
		except KeyError:
			department = 'No department'

		headers = {
			'Content-Type': 'application/json',
			'Authorization': f'Bearer {self.jamf_access_token}'
		}
		
		endpoint = 'v1/computers-inventory-detail/' if device.deviceType == 'macOS' else 'v2/mobile-devices/'

		payload = {
			'userAndLocation': {
				'username': device.ldapUser.username,
				'realname': device.ldapUser.real_name,
				'email': device.ldapUser.email,
				'departmentId': device.ldapUser.department,
				'buildingId': device.ldapUser.building
			}
		}

	#	response = requests.patch(f'https://{self.jamf_host}/api/{endpoint}/{device.id}', headers=headers, json=payload)
	#	response.raise_for_status()
		logging.info(f'Moved {device.name} to deparment {department} and building {building}')
		
	def getLDAPDetails(self, device):
		self.ldap_connection.search('dc=woodleighschool,dc=net', f'(samAccountName={device.jamfUser.username})', attributes=['name', 'mail', 'samAccountName', 'userAccountControl', 'department', 'Campus'])
		logging.debug(f'Getting information from ldap for {device.jamfUser.username}...')
		userAccountState = bin(int(str(self.ldap_connection.entries[0].userAccountControl)))
		if userAccountState[-2] == '1':
			building = '4'
			department = '26'
			disabled = True
		else:
			building = next((key for key, building in buildings.items() if building == str(self.ldap_connection.entries[0].campus)), None)
			department = next((key for key, department in departments.items() if department == str(self.ldap_connection.entries[0].department)), None)
			disabled = False
		
		username = str(self.ldap_connection.entries[0].samAccountName).lower()
		real_name = str(self.ldap_connection.entries[0].name)
		email = str(self.ldap_connection.entries[0].mail)

		user = User(username, building, department, real_name, email, disabled)
		device.ldapUser = user

	def update(self):
		self.__check_token__()

		devices = self.getAllMacDevices()
		devices.extend(self.getAlliOSDevices())

		for device in devices:
			if device.needsToUpdate():
				self.updateUser(device)


def main():
	logging.info('Script started')
	jamf_client_id = os.getenv('JAMF_CLIENT_ID', '')
	jamf_client_secret = os.getenv('JAMF_CLIENT_SECRET', '')
	jamf_host = os.getenv('JAMF_HOST', '')
	ldap_username = os.getenv('LDAP_USERNAME', '')
	ldap_credentials = os.getenv('LDAP_CREDENTIALS', '')
	ldap_host = os.getenv('LDAP_HOST', '')
	update_now = os.getenv('UPDATE_NOW', 'false').lower() == 'true'
	update = UpdateUserInfo(jamf_host, jamf_client_id, jamf_client_secret, ldap_host, ldap_username, ldap_credentials)
	if update_now:
		logging.info('Running update immediately due to UPDATE_NOW setting')
		update.update()
	else:
		cron_schedule = os.getenv('UPDATE_SCHEDULE', '0 0 * * *')
		scheduler = BackgroundScheduler()
		scheduler.add_job(update.update, CronTrigger.from_crontab(cron_schedule))
		scheduler.start()
		logging.info(f'Scheduled update with cron: {cron_schedule}')
		try:
			while True:
				time.sleep(10)
		except (KeyboardInterrupt, SystemExit):
			logging.info('Scheduler shutdown initiated')
			scheduler.shutdown()

if __name__ == '__main__':
	main()



				