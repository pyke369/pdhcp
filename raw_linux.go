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

	"github.com/pyke369/golang-support/uhash"
	"github.com/pyke369/golang-support/ustr"
)

type Addr struct {
	HardwareAddr net.HardwareAddr
	Addr         net.IP
	Port         int
	Device       string
}

type Conn struct {
	Local   *Addr
	bind    *Addr
	version int
	handle  int
	conn    *os.File
}

func NewConn(bind *Addr) (c *Conn, err error) {
	c = &Conn{Local: &Addr{}, bind: bind, version: 4}
	if c.bind == nil {
		c.bind = &Addr{}
	}
	if c.bind.HardwareAddr == nil {
		c.bind.HardwareAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	}
	if c.bind.Addr == nil {
		c.bind.Addr = net.IPv4bcast
	}
	if c.bind.Addr.To4() == nil {
		c.version = 6
	}
	if c.bind.Port < 0 || c.bind.Port > 65535 {
		return nil, errors.New("invalid port " + ustr.Int(c.bind.Port))
	}

	ethertype := (syscall.ETH_P_IP << 8) | (syscall.ETH_P_IP >> 8)
	if c.version == 6 {
		ethertype = (syscall.ETH_P_IPV6 << 8) | (syscall.ETH_P_IPV6 >> 8)
	}
	if c.handle, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, ethertype); err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(c.handle, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(c.handle)
		return nil, err
	}
	if err := syscall.SetNonblock(c.handle, true); err != nil {
		syscall.Close(c.handle)
		return nil, err
	}

	if c.bind.Device != "" {
		if iface, err := net.InterfaceByName(c.bind.Device); err != nil {
			syscall.Close(c.handle)
			return nil, err

		} else if iface.HardwareAddr == nil {
			syscall.Close(c.handle)
			return nil, errors.New("no hardware address for interface " + c.bind.Device)

		} else {
			c.Local.HardwareAddr = iface.HardwareAddr
			if addresses, err := iface.Addrs(); err != nil {
				syscall.Close(c.handle)
				return nil, err

			} else {
				for _, address := range addresses {
					if value, ok := address.(*net.IPNet); ok {
						if !net.IPv4bcast.Equal(bind.Addr) && !net.IPv6linklocalallnodes.Equal(bind.Addr) {
							if (c.version == 4 && value.IP.To4() != nil && value.IP.To4().Equal(bind.Addr)) || value.IP.Equal(bind.Addr) {
								c.Local.Addr = value.IP
								break
							}

						} else if (c.version == 4 && value.IP.To4() != nil) || (c.version == 6 && value.IP.To4() == nil) {
							c.Local.Addr = value.IP
							break
						}
					}
				}
			}
			if err := syscall.Bind(c.handle, &syscall.SockaddrLinklayer{Protocol: uint16(ethertype), Ifindex: iface.Index}); err != nil {
				syscall.Close(c.handle)
				return nil, err
			}
			c.Local.Device = c.bind.Device
			broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
			if !bytes.Equal(c.bind.HardwareAddr, broadcast) && !bytes.Equal(c.bind.HardwareAddr, c.Local.HardwareAddr) {
				// TODO promisicous mode
			}
		}
	}
	if c.conn = os.NewFile(uintptr(c.handle), "rawconn"+ustr.Int(c.handle)); c.conn == nil {
		syscall.Close(c.handle)
		return nil, errors.New("rawconn failed")
	}

	return
}

func (c *Conn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *Conn) ReadFrom(data []byte) (n int, from *Addr, err error) {
	for {
		if n, err = c.conn.Read(data); err != nil {
			return
		}
		if n < 14 {
			continue
		}

		from = &Addr{HardwareAddr: net.HardwareAddr{}, Device: c.Local.Device}
		from.HardwareAddr = append(from.HardwareAddr, data[6:12]...)
		to := Addr{HardwareAddr: net.HardwareAddr{}}
		to.HardwareAddr = append(to.HardwareAddr, data[:6]...)

		switch c.version {
		case 4:
			if n < 42 || data[23] != syscall.IPPROTO_UDP {
				continue
			}
			hsize := int((data[14] & 0x0f) * 4)
			from.Addr = net.IPv4(data[26], data[27], data[28], data[29])
			to.Addr = net.IPv4(data[30], data[31], data[32], data[33])
			from.Port = int(binary.BigEndian.Uint16(data[14+hsize:]))
			to.Port = int(binary.BigEndian.Uint16(data[14+hsize+2:]))
			copy(data, data[14+hsize+8:])
			n -= 14 + hsize + 8

		case 6:
			if n < 62 || data[20] != syscall.IPPROTO_UDP {
				continue
			}
			from.Addr, to.Addr = net.IP{}, net.IP{}
			from.Addr = append(from.Addr, data[22:38]...)
			to.Addr = append(to.Addr, data[38:54]...)
			from.Port = int(binary.BigEndian.Uint16(data[54:]))
			to.Port = int(binary.BigEndian.Uint16(data[56:]))
			copy(data, data[62:])
			n -= 62
		}

		if !c.bind.Addr.Equal(net.IPv4bcast) && !c.bind.Addr.Equal(net.IPv6linklocalallnodes) &&
			!to.Addr.Equal(net.IPv4bcast) && !to.Addr.Equal(net.IPv6linklocalallnodes) &&
			!to.Addr.Equal(c.Local.Addr) && !c.bind.Addr.Equal(to.Addr) {
			continue
		}
		if c.bind.Port != 0 && c.bind.Port != to.Port {
			continue
		}

		return
	}
}

func (c *Conn) WriteTo(from, to *Addr, data []byte) (n int, err error) {
	if to == nil || to.Port == 0 {
		return 0, errors.New("invalid destination port")
	}
	if from == nil {
		from = &Addr{HardwareAddr: c.Local.HardwareAddr, Addr: c.Local.Addr, Port: c.bind.Port}
	}
	if from.HardwareAddr == nil {
		from.HardwareAddr = c.Local.HardwareAddr
	}
	if from.HardwareAddr == nil {
		return 0, errors.New("invalid source hardware address")
	}
	if from.Port == 0 {
		from.Port = c.bind.Port
	}
	if from.Port == 0 {
		return 0, errors.New("invalid source port")
	}

	payload := make([]byte, 0, 62+len(data))
	if c.version == 4 {
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
			to.Addr = net.IPv6linklocalallnodes
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
	if c.version == 4 {
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
		binary.BigEndian.PutUint16(payload[24:], uhash.CRC16(payload[14:34]))
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

	if _, err := c.conn.Write(payload); err != nil {
		return 0, err
	}

	return len(data), nil
}

func BindToDevice(handle int, name string) error {
	return syscall.SetsockoptString(handle, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
}
