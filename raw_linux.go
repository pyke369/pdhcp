//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/ustr"
)

type RawAddr struct {
	HardwareAddr net.HardwareAddr
	Addr         net.IP
	Port         int
	Device       string
}

type RawConn struct {
	Local   *RawAddr
	bind    *RawAddr
	version int
	handle  int
	conn    *os.File
}

func crc16(input []byte) uint16 {
	checksum := 0
	if len(input)%2 != 0 {
		return 0
	}
	for offset := 0; offset < len(input); offset += 2 {
		checksum += int(binary.BigEndian.Uint16(input[offset:]))
	}
	for checksum > 0xffff {
		checksum = (checksum >> 16) + int(uint16(checksum))
	}
	return ^uint16(checksum)
}

func NewRawConn(bind *RawAddr) (rc *RawConn, err error) {
	rc = &RawConn{Local: &RawAddr{}, bind: bind, version: 4}
	if rc.bind == nil {
		rc.bind = &RawAddr{}
	}
	if rc.bind.HardwareAddr == nil {
		rc.bind.HardwareAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	}
	if rc.bind.HardwareAddr == nil {
		return nil, errors.New("invalid bind hardware address")
	}
	if rc.bind.Addr == nil {
		rc.bind.Addr = net.IPv4bcast
	}
	if rc.bind.Addr == nil {
		return nil, errors.New("invalid bind address")
	}
	if rc.bind.Addr.To4() == nil {
		rc.version = 6
	}
	if rc.bind.Port < 0 || rc.bind.Port > 65535 {
		return nil, errors.New("invalid bind port " + ustr.Int(rc.bind.Port))
	}
	ethertype := syscall.ETH_P_IP
	if rc.version == 4 {
		ethertype = (syscall.ETH_P_IP << 8) | (syscall.ETH_P_IP >> 8)
		if rc.handle, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, ethertype); err != nil {
			return nil, err
		}

	} else {
		ethertype = (syscall.ETH_P_IPV6 << 8) | (syscall.ETH_P_IPV6 >> 8)
		if rc.handle, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, ethertype); err != nil {
			return nil, err
		}
	}
	if err := syscall.SetsockoptInt(rc.handle, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}
	if err := syscall.SetNonblock(rc.handle, true); err != nil {
		return nil, err
	}
	if rc.bind.Device != "" {
		if iface, err := net.InterfaceByName(rc.bind.Device); err != nil {
			return nil, errors.New("invalid bind device: " + err.Error())

		} else if iface.HardwareAddr == nil {
			return nil, errors.New("no hardware address for interface " + rc.bind.Device)

		} else {
			rc.Local.HardwareAddr = iface.HardwareAddr
			if addresses, err := iface.Addrs(); err != nil {
				return nil, err

			} else {
				for _, address := range addresses {
					if value, ok := address.(*net.IPNet); ok {
						if rc.version == 4 && value.IP.To4() != nil {
							rc.Local.Addr = value.IP
							break

						} else if rc.version == 6 && value.IP.To4() == nil {
							rc.Local.Addr = value.IP
							break
						}
					}
				}
			}
			if err := syscall.Bind(rc.handle, &syscall.SockaddrLinklayer{Protocol: uint16(ethertype), Ifindex: iface.Index}); err != nil {
				return nil, err
			}
			rc.Local.Device = rc.bind.Device
			broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
			if !bytes.Equal(rc.bind.HardwareAddr, broadcast) && !bytes.Equal(rc.bind.HardwareAddr, rc.Local.HardwareAddr) {
				// TODO set promiscuous mode
			}
		}
	}
	if rc.conn = os.NewFile(uintptr(rc.handle), "rawconn"+ustr.Int(rc.handle)); rc.conn == nil {
		return nil, errors.New("raw conn creation failed")
	}
	return
}

func (rc *RawConn) SetReadDeadline(deadline time.Time) error {
	return rc.conn.SetReadDeadline(deadline)
}

func (rc *RawConn) ReadFrom(data []byte) (read int, from *RawAddr, err error) {
	for {
		if read, err = rc.conn.Read(data); err != nil {
			return
		}
		if read < 14 {
			continue
		}
		from = &RawAddr{HardwareAddr: net.HardwareAddr{}, Device: rc.Local.Device}
		from.HardwareAddr = append(from.HardwareAddr, data[6:12]...)
		to := RawAddr{HardwareAddr: net.HardwareAddr{}}
		to.HardwareAddr = append(to.HardwareAddr, data[:6]...)
		if rc.version == 4 {
			if read < 42 || data[23] != syscall.IPPROTO_UDP {
				continue
			}
			hsize := int((data[14] & 0x0f) * 4)
			from.Addr = net.IPv4(data[26], data[27], data[28], data[29])
			to.Addr = net.IPv4(data[30], data[31], data[32], data[33])
			from.Port = int(binary.BigEndian.Uint16(data[14+hsize:]))
			to.Port = int(binary.BigEndian.Uint16(data[14+hsize+2:]))
			copy(data, data[14+hsize+8:])
			read -= 14 + hsize + 8

		} else {
			if read < 62 || data[20] != syscall.IPPROTO_UDP {
				continue
			}
			from.Addr, to.Addr = net.IP{}, net.IP{}
			from.Addr = append(from.Addr, data[22:38]...)
			to.Addr = append(to.Addr, data[38:54]...)
			from.Port = int(binary.BigEndian.Uint16(data[54:]))
			to.Port = int(binary.BigEndian.Uint16(data[56:]))
			copy(data, data[62:])
			read -= 62
		}
		if !rc.bind.Addr.Equal(net.IPv4bcast) && !rc.bind.Addr.Equal(net.IPv6linklocalallrouters) &&
			!to.Addr.Equal(net.IPv4bcast) && !to.Addr.Equal(net.IPv6linklocalallrouters) &&
			!to.Addr.Equal(rc.Local.Addr) && !rc.bind.Addr.Equal(to.Addr) {
			continue
		}
		if rc.bind.Port != 0 && rc.bind.Port != to.Port {
			continue
		}
		return
	}
}

func (rc *RawConn) WriteTo(from, to *RawAddr, data []byte) (written int, err error) {
	if to == nil || to.Port == 0 {
		return 0, errors.New("invalid destination port")
	}
	if from == nil {
		from = &RawAddr{HardwareAddr: rc.Local.HardwareAddr, Addr: rc.Local.Addr, Port: rc.bind.Port}
	}
	if from.HardwareAddr == nil {
		from.HardwareAddr = rc.Local.HardwareAddr
	}
	if from.HardwareAddr == nil {
		return 0, errors.New("invalid source hardware address")
	}
	if from.Port == 0 {
		from.Port = rc.bind.Port
	}
	if from.Port == 0 {
		return 0, errors.New("invalid source port")
	}

	payload := make([]byte, 0, 62+len(data))
	if rc.version == 4 {
		if to.Addr == nil {
			to.Addr = net.IPv4bcast
		}
		if to.HardwareAddr == nil {
			to.HardwareAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
		}
		if from.Addr == nil {
			from.Addr = net.IPv4zero
		}

	} else {
		if to.Addr == nil {
			to.Addr = net.IPv6linklocalallrouters
		}
		if to.HardwareAddr == nil {
			to.HardwareAddr, _ = net.ParseMAC(ustr.Hex([]byte{0x33, 0x33, to.Addr[12], to.Addr[13], to.Addr[14], to.Addr[15]}, ':'))
		}
		if from.Addr == nil {
			from.Addr = net.IPv6unspecified
		}
	}

	// ETH destination and source addresses
	payload = append(payload, to.HardwareAddr...)
	payload = append(payload, from.HardwareAddr...)
	if rc.version == 4 {
		// ETH ethertype
		payload = append(payload, byte(syscall.ETH_P_IP>>8), byte(syscall.ETH_P_IP&0xff))
		// IP4 header
		ilength, ulength := 28+len(data), 8+len(data)
		payload = append(payload, []byte{
			// IP4 version/hlength + TOS + length
			0x45, 0x10, byte(ilength >> 8), byte(ilength),
			// IP4 id + flags + offset
			0x00, 0x00, 0x00, 0x00,
			// IP4 ttl + protocol + checksum (overwritten below)
			128, 17, 0x00, 0x00,
		}...)
		// IP4 source address
		payload = append(payload, from.Addr.To4()...)
		// IP4 destination address
		payload = append(payload, to.Addr.To4()...)
		// IP4 header crc
		binary.BigEndian.PutUint16(payload[24:], crc16(payload[14:34]))
		// UDP header
		payload = append(payload, []byte{
			// UDP source + destination ports
			byte(from.Port >> 8), byte(from.Port), byte(to.Port >> 8), byte(to.Port),
			// UDP length + checksum (unused)
			byte(ulength >> 8), byte(ulength), 0x00, 0x00,
		}...)

	} else {
		// ETH ethertype
		payload = append(payload, byte(syscall.ETH_P_IPV6>>8), byte(syscall.ETH_P_IPV6&0xff))
		// IP6 header
		length := 8 + len(data)
		payload = append(payload, []byte{
			// IP6 version + traffic class + flow label
			0x60, 0x00, 0x00, 0x00,
			// IP6 length + next header + hop limit
			byte(length >> 8), byte(length), 17, 1,
		}...)
		// IP6 source address
		payload = append(payload, from.Addr...)
		// IP4 destination address
		payload = append(payload, to.Addr...)
		// UDP header
		payload = append(payload, []byte{
			// UDP source + destination ports
			byte(from.Port >> 8), byte(from.Port), byte(to.Port >> 8), byte(to.Port),
			// UDP length + checksum (unused)
			byte(length >> 8), byte(length), 0x00, 0x00,
		}...)
	}
	payload = append(payload, data...)

	if _, err := rc.conn.Write(payload); err != nil {
		return 0, err
	}
	return len(data), nil
}

func BindToDevice(handle int, name string) error {
	return syscall.SetsockoptString(handle, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
}
