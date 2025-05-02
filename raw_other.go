//go:build !linux && !freebsd && !openbsd && !netbsd && !darwin
// +build !linux,!freebsd,!openbsd,!netbsd,!darwin

package main

import (
	"errors"
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
	return nil
}
