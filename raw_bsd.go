//go:build freebsd || openbsd || netbsd || darwin

package main

import (
	"errors"
	"net"
	"syscall"
	"time"
)

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
	return nil, errors.New("not implemented")
}

func (rc *RawConn) SetReadDeadline(deadline time.Time) error {
	return errors.New("not implemented")
}

func (rc *RawConn) ReadFrom(data []byte) (read int, from *RawAddr, err error) {
	return 0, nil, errors.New("not implemented")
}

func (rc *RawConn) WriteTo(from, to *RawAddr, data []byte) (written int, err error) {
	return 0, errors.New("not implemented")
}

func BindToDevice(handle int, name string) error {
	info, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	return syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, syscall.IP_BOUND_IF, info.Index)
}
