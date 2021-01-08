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
 All options (```python3 autocap.py -h```):
 ```
 usage: autocap.py [-h] [-i interface] [--conf confidence] [--pAm packets] [--dir directory]
                  [--mode mode]
                  network_name

 Automatically capture handshake

 positional arguments:
	network_name       Network name

 optional arguments:
	-h, --help         show this help message and exit
	-i interface       Interface
	--conf confidence  Confidence in guessing network name (default = 0.6)
	--pAm packets      Amount of packets to send (default = 5)
	--dir directory    Directory (default = mydir/wifis/network_name)
	--mode mode        Set to pi if you are using raspberry

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