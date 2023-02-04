// +build !linux,!freebsd,!openbsd,!netbsd,!darwin

package main

import (
	"fmt"
	"net"
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
	return nil
}
