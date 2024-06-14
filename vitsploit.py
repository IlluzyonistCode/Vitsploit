import ipaddress
from colorama import Fore, Style, init
from webscan import WebScan
from exscan import exscan
from printer import cprint, fail

init()


def check_host(host):
    try:
        ip = ipaddress.ip_address(host)
        
        return True
    except ValueError:
        return False


def run():
	cprint('{byellow}Vit{bred}sploit{rst}\n', mark=None)

	target = input(f'{Style.BRIGHT}{Fore.RED}Target IP:{Fore.RESET} ')

	if check_host(target):
		ws = WebScan()
		ws.scan_host(target)

		exscan(target)

	else:
		fail('Invalid IP.')


try:
	run()
except KeyboardInterrupt:
	pass
