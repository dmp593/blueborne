import bluetooth
import json
from mcif.util import merge_dicts


class Guesser:
    def __init__(self):
        file = open('./mcif/devices.json', 'r')
        self.manufacturers = json.load(file)
        file.close()

    def search(self):
        print('searching for devices...')
        return bluetooth.discover_devices(duration=10, lookup_names=True)

    def is_device_vulnerable(self, addr):
        for (manufacturer, macs) in self.manufacturers.items():
            for mac in macs:
                if mac == addr[:8]:
                    return True
        return False

    def attempt(self):
        macs = {}

        results = self.search()

        if (results is None):
            pass

        for addr, name in results:
            vulnerable = self.is_device_vulnerable(addr)

            if (vulnerable):
                print ('%s | %s -> IS VULNERABLE' % (addr, name))
                macs[addr] = name
            else:
                print ('%s | %s -> not vulnerable' % (addr, name))

        return macs

    def guess(self, attempts=3):
        macs = {}

        try:
            for attempt in range(attempts):
                print('Attempt: %d' % attempt)
                macs = merge_dicts(macs, self.attempt())

            return macs
        except (Exception):
            pass
