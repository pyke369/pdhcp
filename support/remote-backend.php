<?php
$request = @json_decode(@file_get_contents('php://input'), true);
$msgtype = @$request['dhcp-message-type'];
if ($msgtype == 'discover' || $msgtype == 'request')
{
    $filename = (@$request['client-system'] == 7 ? 'ipxe.efi' : 'undionly.kpxe');
    if ($request['user-class'] == 'iPXE')
    {
        $filename = 'http://192.168.40.1/ipxe.php?mac=${net0/mac}';
    }
    $response =
    [
        'dhcp-message-type'       => ($msgtype == 'discover' ? 'offer' :'ack'),
        'client-hardware-address' => @$request['client-hardware-address'],
        'bootp-transaction-id'    => @$request['bootp-transaction-id'],
        'hostname'                => 'server',
        'bootp-assigned-address'  => (@$request['bootp-client-address'] != '' ? $request['bootp-client-address'] : '192.168.40.150'),
        'subnet-mask'             => '255.255.255.0',
        'routers'                 => [ '192.168.40.1' ],
        'domain-name-servers'     => [ '192.168.40.1' ],
        'domain-name'             => 'domain.com',
        'address-lease-time'      => 604800,
        'bootp-server-address'    => '192.168.40.1',
        'bootp-filename'          => $filename
    ]; 
    header('Content-Type: application/json');
    print json_encode($response);
}
