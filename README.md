# autocap
 Automated packet capture and client deauth for later cracking.
 This project was initially created for raspberry pi with external wifi adapater.
## Installation
 ```
 git clone https://github.com/Cod3dDOT/autocap
 cd autocap
 pip3 install -r requirements.txt
 ```
## Usage
 Default (Linux):
 ```
 python3 autocap.py network_name -i interface
 ```
 Raspberries (Raspberry OS):
 ```
 python3 autocap.py network_name -i interface --mode pi
 ```
 For all options:
 ```
 python3 autocap.py -h
 ```
## Dependecies
 aircrack-ng:
 ```
 sudo apt-get install aircrack-ng
 ```
 termcolor:
 ```
 pip3 install termcolor
 ```