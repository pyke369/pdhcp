// +build freebsd openbsd netbsd darwin

package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// TODO provide implementation based on BPF

type RawAddr struct {
	HardwareAddr net.HardwareAddr
	Addr         net.IP
	Port         int
	Device       string
}

type RawConn struct {
	Local *RawAddr
}

func NewRawConn(bind *RawAddr) (rc *RawConn, err error) {
	return nil, fmt.Errorf("not implemented")
}

func (rc *RawConn) SetReadDeadline(deadline time.Time) error {
	return fmt.Errorf("not implemented")
}

func (rc *RawConn) ReadFrom(data []byte) (read int, from *RawAddr, err error) {
	return 0, nil, fmt.Errorf("not implemented")
}

func (rc *RawConn) WriteTo(from, to *RawAddr, data []byte) (written int, err error) {
	return 0, fmt.Errorf("not implemented")
}

func BindToDevice(handle int, name string) error {
	info, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	return syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, syscall.IP_BOUND_IF, info.Index)
}
