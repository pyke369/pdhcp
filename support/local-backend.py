#!/usr/bin/env python3

import sys, json

while True:
    try:
        request = json.loads(sys.stdin.readline())
        sys.stderr.write('recv ' + json.dumps(request) + "\n")
        msgtype = request.get('dhcp-message-type', '')
        if msgtype == 'discover' or msgtype == 'request':
            # filename = 'ipxe.efi' if request.get('client-system', 0) == 7 else 'undionly.kpxe'
            # if request.get('user-class') == 'iPXE':
            #     filename = 'http://192.168.23.254/ipxe.php?mac=${net0/mac}'
            response = {
                'dhcp-message-type':       'offer' if msgtype == 'discover' else 'ack',
                'client-hardware-address': request.get('client-hardware-address', ''),
                'bootp-transaction-id':    request.get('bootp-transaction-id', ''),
                'hostname':                'server01',
                'bootp-assigned-address':  request.get('bootp-client-address', '192.168.23.1'),
                'subnet-mask':             '255.255.255.0',
                'routers':                 [ '192.168.23.254' ],
                'domain-name-servers':     [ '192.168.23.254' ],
                'domain-name':             'domain.com',
                'address-lease-time':      604800,
                # 'bootp-server-address':    '192.168.23.254',
                # 'bootp-filename':          filename
            }
            sys.stderr.write('send ' + json.dumps(response) + "\n")
            sys.stdout.write(json.dumps(response) + '\n')
            sys.stdout.flush()

    except:
        break
