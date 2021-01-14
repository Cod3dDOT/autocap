# autocap
 Automated packet capture and client deauth for later cracking.
 This project was initially created for Raspberry Pi with external wifi adapater.
 Written in Python, support both Python2 and Python3.
 ![autocap demo](/demo/autocap_demo.svg)
## Installation
 ```
 git clone https://github.com/Cod3dDOT/autocap
 cd autocap
 pip install -r requirements.txt
 ```
## Usage
 Default:
 ```
 python3 autocap.py NETWORK_NAME -i interface
 ```
 Retain internet connection:
 ```
 python3 autocap.py NETWORK_NAME -i interface --nokill
 ```
 This will not kill wifi processes, allowing you to control your pi from other network. May not work depending upon your software/firmware.
 
 All options ```python3 autocap.py -h```:
 ```
 usage: autocap.py [-h] [-i INTERFACE] [--conf CONFIDENCE] [--pack PACKETS] [--dir DIRECTORY]
                  [--nokill]
                  NETWORK_NAME

 Automatically capture handshake

 positional arguments:
	NETWORK_NAME       Network name

 optional arguments:
	-h, --help         show this help message and exit
	-i interface       Interface
	--conf confidence  Confidence in guessing network name from 0 to 1 (default = 0.6)
	--pAm packets      Amount of packets to send (default = 10)
	--dir directory    Directory, in which .cap file is stored (default = mydirectory/wifis/NETWORK_NAME/)
	--nokill           Specify if you don't want to kill processes. May not work depending upon your software/firmware
 ```
## Dependecies
 aircrack-ng:
 ```
 sudo apt-get install aircrack-ng
 ```
 termcolor:
 ```
 pip install termcolor
 ```