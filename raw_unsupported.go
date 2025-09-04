//go:build !linux

package main

import (
	"errors"
	"time"
)

type Addr struct{}

type Conn struct{}

func NewConn(bind *RawAddr) (conn *Conn, err error) {
	return nil, errors.ErrUnsupported
}

func (c *Conn) SetReadDeadline(deadline time.Time) error {
	return errors.ErrUnsupported
}

func (c *Conn) ReadFrom(data []byte) (n int, from *Addr, err error) {
	return 0, nil, errors.ErrUnsupported
}

func (c *Conn) WriteTo(from, to *Addr, data []byte) (n int, err error) {
	return 0, errors.ErrUnsupported
}

func BindToDevice(handle int, name string) error {
	return nil
}
