#!/usr/bin/env python

import os, sys, select, fcntl
try:
    import simplejson as json
except ImportError:
    import json

fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK)
while True:
    ready, _, _ = select.select([sys.stdin], [], [], 2)
    if ready:
        while True:
            try:
                line = sys.stdin.readline().strip()
                if line == '':
                    os._exit(0)
                request  = json.loads(line)
                sys.stderr.write('--- received request ---\n' + json.dumps(request, indent = 4))
                response = {
                   'dhcp-message-type':       'offer' if request.get('dhcp-message-type', '') == 'discover' else 'ack',
                   'client-hardware-address': request.get('client-hardware-address', ''),
                   'bootp-transaction-id':    request.get('bootp-transaction-id', ''),
                   'server-identifier':       '192.168.37.128',
                   'hostname':                'server',
                   'bootp-assigned-address':  request.get('bootp-client-address', '192.168.37.192'),
                   'subnet-mask':             '255.255.255.0',
                   'routers':                 [ '192.168.37.2' ],
                   'domain-name-servers':     [ '192.168.37.2' ],
                   'domain-name':             'domain.com',
                   'address-lease-time':      2592000,
                   'bootp-server-address':    '192.168.37.128',
                   'bootp-filename':          'pxelinux.0'
                }
                sys.stderr.write('--- sent response ---\n' + json.dumps(response, indent = 4))
                sys.stdout.write(json.dumps(response) + '\n')
                sys.stdout.flush()
            except:
                break
    else:
        sys.stdout.write('{}\n')
        sys.stdout.flush()
