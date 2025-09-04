package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/fqdn"
	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/multiflag"
	"github.com/pyke369/golang-support/uhash"
	"github.com/pyke369/golang-support/ulog"
	"github.com/pyke369/golang-support/ustr"
	"golang.org/x/sys/unix"
)

const PROGNAME = "pdhcp"
const PROGVER = "2.3.0"

type SOURCE struct {
	rconn *Conn
	pconn net.PacketConn
}

type PACKET struct {
	source   string
	hardware string
	client   string
	data     []byte
}

type CONTEXT struct {
	created time.Time
	source  string
	client  string
	data    FRAME
}

func bail(message string, extra ...int) {
	if message != "" {
		os.Stderr.WriteString(message + " - aborting\n")
	}
	if len(extra) > 0 {
		os.Exit(extra[0])
	}
	if message != "" {
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	var flags flag.FlagSet

	flags = flag.FlagSet{Usage: func() {
		os.Stderr.WriteString("usage: " + filepath.Base(os.Args[0]) + " [<option>...]\n\noptions are:\n")
		flags.PrintDefaults()
	}}
	headers := multiflag.Multiflag{}
	version := flags.Bool("v", j.Boolean(os.Getenv("PDHCP_VERSION")), "show program version")
	list1 := flags.Bool("l", j.Boolean(os.Getenv("PDHCP_LIST")), "list available DHCP options (human format)")
	list2 := flags.Bool("j", j.Boolean(os.Getenv("PDHCP_LIST_JSON")), "list available DHCP options (JSON format)")
	v6 := flags.Bool("6", j.Boolean(os.Getenv("PDHCP_V6")), "run in IPv6 mode")
	interfaces := flags.String("i", os.Getenv("PDHCP_INTERFACES"), "use specified interface(s)")
	backend := flags.String("b", os.Getenv("PDHCP_BACKEND"), "set backend command/url")
	workers := flags.Int("w", int(j.Number(os.Getenv("PDHCP_WORKERS"), 1)), "set workers count (local backend)")
	relay := flags.String("r", os.Getenv("PDHCP_RELAY"), "set remote DHCP server address (relay mode)")
	arelay := flags.String("s", os.Getenv("PDHCP_RELAY_ADDRESS"), "use specified alternate relay local address (relay mode)")
	extra := flags.String("R", os.Getenv("PDHCP_BACKEND"), "overload default options (client mode)")
	address := flags.String("a", j.String(os.Getenv("PDHCP_ADDRESS"), "*"), "use alternate address (server/relay modes)")
	port := flags.Int("p", int(j.Number(os.Getenv("PDHCP_PORT"), 67)), "use alternate port (server/relay modes)")
	format := flags.String("f", os.Getenv("PDHCP_FORMAT"), "use alternate logging format")
	pretty := flags.Bool("P", j.Boolean(os.Getenv("PDHCP_PRETTY")), "pretty-print JSON")
	dump := flags.Bool("d", j.Boolean(os.Getenv("PDHCP_DUMP")), "dump request (client mode)")
	insecure := flags.Bool("I", j.Boolean(os.Getenv("PDHCP_INSECURE")), "allow insecure TLS connections (remote backend)")
	flags.Var(&headers, "H", "add HTTP header (remote backend / repeatable)")
	cert := flags.String("c", os.Getenv("PDHCP_CERT"), "use client certificate (remote backend)")
	cacert := flags.String("C", os.Getenv("PDHCP_CACERT"), "use CA certificate (remote backend)")
	timeout := flags.Int("t", int(j.Number(os.Getenv("PDHCP_PORT"), 7)), "set backend timeout")
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "PDHCP_") {
			os.Setenv(env, "")
		}
	}
	if err := flags.Parse(os.Args[1:]); err != nil {
		bail("", 1)
	}

	*timeout = min(30, max(3, *timeout))
	*workers = min(32, max(1, *workers))

	mode := "client"
	if *backend != "" {
		mode = "server"

	} else if *relay != "" {
		mode = "relay"
	}
	if _, _, err := net.SplitHostPort(*relay); err != nil {
		*relay += ":67"
	}

	if *version {
		os.Stdout.WriteString(PROGNAME + " v" + PROGVER + "\n")
		os.Exit(0)
	}
	if *list1 || *list2 {
		v4options(*list2, *pretty)
		os.Exit(0)
	}
	if *v6 {
		bail("IPv6 is not implemented")
	}

	if *format == "" {
		*format = "console(output=stderr,time=msdatetime) syslog(facility=local0)"
	}
	logger := ulog.New(*format)
	logger.SetOrder([]string{
		"event", "bind", "mode", "version", "pid", "txid", "type", "local", "worker", "remote",
		"interface", "client", "address", "hostname", "duration", "relay", "reason", "status",
	})
	if mode != "client" {
		logger.Info(map[string]any{"event": "start", "mode": mode, "version": PROGVER, "pid": os.Getpid()})
	}

	var mu sync.RWMutex

	packets, frames, sources, contexts := make(chan PACKET, 1024), make(chan FRAME, 1024), map[string]*SOURCE{}, map[string]*CONTEXT{}
	if mode == "server" {
		if strings.HasPrefix(*backend, "http") {
			go func() {
				for {
					go func(frame FRAME) {
						if payload, err := json.Marshal(frame); err == nil {
							if request, err := http.NewRequest(http.MethodPost, *backend, bytes.NewBuffer(payload)); err == nil {
								request.Header.Set("Content-Length", strconv.Itoa(len(payload)))
								request.Header.Set("Content-Type", "application/json")
								request.Header.Set("User-Agent", PROGNAME+"/"+PROGVER)
								for _, header := range headers {
									request.Header.Set(header[0], header[1])
								}
								remote, _ := url.Parse(request.URL.String())
								remote.User, remote.RawQuery = nil, ""
								remote, _ = url.Parse(remote.String())
								logger.Info(map[string]any{
									"event":  "send",
									"type":   j.String(frame["dhcp-message-type"]),
									"txid":   j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
									"remote": remote.String(),
								})

								transport := &http.Transport{TLSClientConfig: &tls.Config{
									InsecureSkipVerify: *insecure,
								}}
								if path := strings.TrimSpace(*cacert); path != "" {
									if content, err := os.ReadFile(path); err == nil {
										if der, _ := pem.Decode(content); der != nil && der.Type == "CERTIFICATE" {
											if cert, err := x509.ParseCertificate(der.Bytes); err == nil && cert.IsCA {
												pool := x509.NewCertPool()
												pool.AddCert(cert)
												transport.TLSClientConfig.RootCAs = pool
											}
										}
									}
								}
								if parts := strings.Split(*cert, ","); len(parts) == 2 {
									if cert, err := tls.LoadX509KeyPair(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])); err == nil {
										transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
									}
								}

								client := &http.Client{
									Timeout:   time.Duration(*timeout) * time.Second,
									Transport: transport,
								}
								if response, err := client.Do(request); err == nil {
									payload, _ := io.ReadAll(response.Body)
									response.Body.Close()

									frame := FRAME{}
									if err := json.Unmarshal(payload, &frame); err == nil {
										mu.RLock()
										if contexts[v4key(frame)] != nil {
											if packet, err := v4build(frame); err == nil {
												logger.Info(map[string]any{
													"event":  "recv",
													"type":   j.String(frame["dhcp-message-type"]),
													"txid":   j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
													"remote": remote.String(),
												})
												packets <- PACKET{source: "http", client: *backend, data: packet}
											}
										}
										mu.RUnlock()
									}

								} else {
									logger.Warn(map[string]any{
										"event":  "recv",
										"type":   j.String(frame["dhcp-message-type"]),
										"txid":   j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
										"remote": remote.String(),
										"reason": err.Error(),
									})
								}
							}
						}
					}(<-frames)
				}
			}()

		} else {
			for *workers > 0 {
				go func() {
					for {
						parts := strings.Split(*backend, " ")
						if path, err := exec.LookPath(parts[0]); err == nil {
							parts[0] = filepath.Base(parts[0])
							cmd, pid := &exec.Cmd{Path: path, Args: parts, Stderr: os.Stderr}, 0
							if stdin, err := cmd.StdinPipe(); err == nil {
								if stdout, err := cmd.StdoutPipe(); err == nil {
									if err := cmd.Start(); err == nil {
										pid = cmd.Process.Pid
										logger.Info(map[string]any{
											"event":  "start",
											"local":  cmd.Path,
											"worker": pid,
										})
										queue := make(chan FRAME)

										go func() {
											reader := bufio.NewReader(stdout)
											for {
												if line, err := reader.ReadString('\n'); err != nil {
													queue <- nil
													break

												} else {
													var frame FRAME

													if err := json.Unmarshal([]byte(line), &frame); err == nil {
														mu.RLock()
														if contexts[v4key(frame)] != nil {
															queue <- frame
														}
														mu.RUnlock()

													} else {
														cmd.Process.Kill()
													}
												}
											}
										}()

									loop:
										for {
											select {
											case frame := <-frames:
												if payload, err := json.Marshal(frame); err == nil {
													payload = append(payload, '\n')
													if _, err := stdin.Write(payload); err == nil {
														logger.Info(map[string]any{
															"event":  "send",
															"type":   j.String(frame["dhcp-message-type"]),
															"txid":   j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
															"local":  cmd.Path,
															"worker": pid,
														})
													}
												}

											case frame := <-queue:
												if frame == nil {
													break loop
												}
												if packet, err := v4build(frame); err == nil {
													logger.Info(map[string]any{
														"event":  "recv",
														"type":   j.String(frame["dhcp-message-type"]),
														"txid":   j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
														"local":  cmd.Path,
														"worker": pid,
													})
													packets <- PACKET{source: "worker", client: strconv.Itoa(pid), data: packet}
												}
											}
										}
									}
								}
							}
							err, status := cmd.Wait(), "normal exit"
							if err != nil {
								status = err.Error()
							}
							logger.Warn(map[string]any{
								"event":  "stop",
								"local":  cmd.Path,
								"worker": pid,
								"status": status,
							})
						}
						time.Sleep(3 * time.Second)
					}
				}()
				*workers--
			}
		}
	}

	if mode == "client" {
		if *interfaces == "" {
			bail("no interface specified")
		}

		conn, err := NewConn(&Addr{Port: *port + 1, Device: *interfaces})
		if err != nil {
			bail(err.Error())
		}
		for try := 3; try <= 5; try++ {
			txid := uhash.Rand(1<<32 - 1)
			frame := map[string]any{
				"bootp-transaction-id":    ustr.HexInt(uint64(txid), 4),
				"bootp-broadcast":         true,
				"dhcp-message-type":       "discover",
				"client-hardware-address": conn.Local.HardwareAddr.String(),
				"parameters-request-list": []any{"hostname", "subnet-mask", "routers", "domain-name", "domain-name-servers", "domain-search", "classless-route", "time-offset", "ntp-servers"},
			}
			if conn.Local.Addr != nil {
				frame["requested-ip-address"] = conn.Local.Addr.String()
			}
			hostname, _ := fqdn.FQDN()
			if hostname != "" && hostname != "unknown" {
				frame["hostname"] = hostname
			}
			if *extra != "" {
				var eframe map[string]any

				if err := json.Unmarshal([]byte(*extra), &eframe); err != nil {
					bail(err.Error())
				}
				for name, value := range eframe {
					frame[name] = value
				}
			}
			from, to := &Addr{}, &Addr{Port: *port}
			if value := j.String(frame["bootp-client-address"]); value != "" {
				from.Addr = net.ParseIP(value)
			}

			if packet, err := v4build(frame); err == nil {
				if *dump {
					content, err := json.Marshal(frame)
					if *pretty {
						content, err = json.MarshalIndent(frame, "", "  ")
						content = append([]byte("> request "), bytes.ReplaceAll(content, []byte("\n"), []byte("\n> "))...)
						content = append(content, '\n')
					}
					if err == nil {
						os.Stdout.Write(append(content, '\n'))
					}
				}
				if _, err := conn.WriteTo(from, to, packet); err == nil {
					conn.SetReadDeadline(time.Now().Add(time.Duration(try) * time.Second))
					packet := make([]byte, 4<<10)
					for {
						read, _, err := conn.ReadFrom(packet)
						if err != nil {
							break
						}
						if rframe, err := v4parse(packet[:read]); err == nil {
							if rframe["bootp-opcode"] == "reply" &&
								rframe["client-hardware-address"] == frame["client-hardware-address"] &&
								rframe["bootp-transaction-id"] == frame["bootp-transaction-id"] {
								if mrequest, ok := frame["dhcp-message-type"].(string); ok {
									if mresponse, ok := rframe["dhcp-message-type"].(string); ok {
										if response := V4MSGTYPES[V4RMSGTYPES[mresponse]]; response != nil &&
											(response.request == 0 || response.request == V4RMSGTYPES[mrequest]) {
											content, err := json.Marshal(rframe)
											if *pretty {
												content, err = json.MarshalIndent(rframe, "", "  ")
												content = append([]byte("< response "), bytes.ReplaceAll(content, []byte("\n"), []byte("\n< "))...)
											}
											if err == nil {
												os.Stdout.Write(append(content, '\n'))
												bail("")
											}
											bail(err.Error())
										}
									}
								}
							}
						}
					}

				} else {
					bail(err.Error())
				}

			} else {
				bail(err.Error())
			}
		}
		bail("no response from server")

	} else {
		interfaces := strings.Trim(*interfaces, ",")
		if interfaces != "" {
			interfaces += ","
		}
		for _, name := range strings.Split(interfaces, ",") {
			go func(name string) {
				source := &SOURCE{}
				if name != "" {
					if conn, err := NewConn(&Addr{Port: *port, Device: name}); err == nil {
						if conn.Local.Addr == nil {
							logger.Warn(map[string]any{
								"event":  "bind",
								"bind":   name + "@" + *address + ":" + strconv.Itoa(*port),
								"reason": "skipping interface " + name + ": no address",
							})
							return
						}
						source.rconn = conn
						logger.Info(map[string]any{
							"event":     "bind",
							"bind":      *address + ":" + strconv.Itoa(*port) + "@" + name,
							"interface": conn.Local.HardwareAddr.String() + "@" + conn.Local.Addr.String(),
						})

					} else if mode == "relay" {
						config := net.ListenConfig{
							Control: func(network, address string, connection syscall.RawConn) error {
								connection.Control(func(handle uintptr) {
									syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
									syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
									BindToDevice(int(handle), name)
								})
								return nil
							},
						}
						if conn, err := config.ListenPacket(context.Background(), "udp", strings.TrimPrefix(*address+":"+strconv.Itoa(*port), "*")); err == nil {
							source.pconn = conn
							logger.Info(map[string]any{
								"event": "bind",
								"bind":  *address + ":" + strconv.Itoa(*port) + "@" + name,
								"relay": *relay,
							})

						} else {
							logger.Warn(map[string]any{
								"event":  "bind",
								"bind":   *address + ":" + strconv.Itoa(*port) + "@" + name,
								"relay":  *relay,
								"reason": "skipping interface " + name + ": " + err.Error(),
							})
							return
						}

					} else {
						logger.Warn(map[string]any{
							"event":  "bind",
							"bind":   *address + ":" + strconv.Itoa(*port) + "@" + name,
							"reason": "skipping interface " + name + ": " + err.Error(),
						})
						return
					}

				} else {
					name = "-"
					config := net.ListenConfig{
						Control: func(network, address string, connection syscall.RawConn) error {
							connection.Control(func(handle uintptr) {
								syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
								syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
							})
							return nil
						}}
					if conn, err := config.ListenPacket(context.Background(), "udp", strings.TrimPrefix(*address+":"+strconv.Itoa(*port), "*")); err == nil {
						source.pconn = conn
						logger.Info(map[string]any{
							"event": "bind",
							"bind":  *address + ":" + strconv.Itoa(*port),
							"mode":  mode,
						})

					} else {
						logger.Warn(map[string]any{
							"event":  "bind",
							"bind":   *address + ":" + strconv.Itoa(*port),
							"mode":   mode,
							"reason": err.Error(),
						})
						return
					}
				}
				mu.Lock()
				sources[name] = source
				mu.Unlock()

				for {
					packet := [4 << 10]byte{}
					if source.rconn != nil {
						if read, from, err := source.rconn.ReadFrom(packet[:]); err == nil {
							packets <- PACKET{source: name, hardware: from.HardwareAddr.String(), client: from.Addr.String() + ":" + strconv.Itoa(from.Port), data: packet[:read]}
						}

					} else if source.pconn != nil {
						if read, from, err := source.pconn.ReadFrom(packet[:]); err == nil {
							packets <- PACKET{source: name, client: from.String(), data: packet[:read]}
						}
					}
				}
			}(strings.TrimSpace(name))
		}

		go func() {
			for {
				now := time.Now()
				mu.Lock()
				for key, context := range contexts {
					if now.Sub(context.created) >= 10*time.Second {
						delete(contexts, key)
					}
				}
				mu.Unlock()
				time.Sleep(time.Second)
			}
		}()

		for {
			packet := <-packets
			frame, err := v4parse(packet.data)
			if err != nil {
				continue
			}

			key := v4key(frame)
			if frame["bootp-opcode"] == "request" {
				if j.String(frame["bootp-relay-address"]) != "" {
					if packet.source != "-" {
						continue
					}

				} else if packet.source == "-" {
					continue

				} else if value := j.String(frame["bootp-client-address"]); value != "" {
					if host, _, err := net.SplitHostPort(packet.client); err == nil && value != host {
						continue
					}
				}
				if value := j.String(frame["server-identifier"]); value != "" && sources[packet.source].rconn != nil {
					if value != sources[packet.source].rconn.Local.Addr.String() {
						continue
					}
				}
				if value := j.String(frame["client-hardware-address"]); value != "" && packet.hardware != "" && packet.hardware != value {
					continue
				}
				mu.Lock()
				if contexts[key] != nil {
					mu.Unlock()
					break
				}
				contexts[key] = &CONTEXT{time.Now(), packet.source, packet.client, frame}
				mu.Unlock()
				logger.Info(map[string]any{
					"event":     "request",
					"type":      j.String(frame["dhcp-message-type"]),
					"txid":      j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
					"interface": packet.source,
					"client":    packet.client,
					"address":   j.String(frame["requested-ip-address"]),
					"hostname":  j.String(frame["hostname"]),
				})

				if mode == "relay" {
					rframe, _ := v4parse(packet.data)
					rframe["bootp-relay-hops"] = int(j.Number(rframe["bootp-hops"])) + 1
					if *arelay != "" {
						rframe["bootp-relay-address"] = *arelay

					} else {
						rframe["bootp-relay-address"] = sources[packet.source].rconn.Local.Addr.String()
					}
					delete(rframe, "bootp-broadcast")
					if rpacket, err := v4build(rframe); err == nil {
						if raddress, err := net.ResolveUDPAddr("udp", *relay); err == nil {
							if _, err := sources["-"].pconn.WriteTo(rpacket, raddress); err == nil {
								logger.Info(map[string]any{
									"event": "send",
									"type":  j.String(rframe["dhcp-message-type"]),
									"txid":  j.String(rframe["client-hardware-address"]) + "/" + j.String(rframe["bootp-transaction-id"]),
									"relay": *relay,
								})
							}
						}
					}

				} else {
					if sources[packet.source].rconn != nil {
						frame["source-address"] = sources[packet.source].rconn.Local.Addr.String()
					}
					select {
					case frames <- frame:

					default:
					}
				}

			} else {
				mu.RLock()
				ctx := contexts[key]
				mu.RUnlock()
				if ctx == nil {
					break
				}
				client := ctx.client
				if address, port, err := net.SplitHostPort(ctx.client); err == nil {
					if value, ok := ctx.data["bootp-broadcast"].(bool); (ok && value) || net.ParseIP(address).Equal(net.IPv4zero) {
						client = net.IPv4bcast.String() + ":" + port
						frame["bootp-broadcast"] = value
					}
					if value := j.String(ctx.data["bootp-relay-address"]); value != "" {
						client = value + ":" + port
						frame["bootp-relay-address"] = value
					}

				} else {
					break
				}
				if mode == "relay" {
					logger.Info(map[string]any{
						"event": "recv",
						"type":  j.String(frame["dhcp-message-type"]),
						"txid":  j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
						"relay": *relay,
					})
				}
				if sources[ctx.source].rconn != nil && sources[ctx.source].rconn.Local.Addr != nil {
					frame["server-identifier"] = sources[ctx.source].rconn.Local.Addr.String()
				}
				packet, _ := v4build(frame)
				if sources[ctx.source].rconn != nil {
					if address, value, err := net.SplitHostPort(client); err == nil {
						port, _ := strconv.Atoi(value)
						to := &Addr{Addr: net.ParseIP(address), Port: port}
						if !to.Addr.Equal(net.IPv4bcast) && !to.Addr.Equal(net.IPv6linklocalallrouters) {
							to.HardwareAddr, _ = net.ParseMAC(frame["client-hardware-address"].(string))
						}
						if _, err := sources[ctx.source].rconn.WriteTo(nil, to, packet); err != nil {
							logger.Warn(map[string]any{"event": "reply", "reason": err.Error()})
							break
						}

					} else {
						logger.Warn(map[string]any{"event": "reply", "reason": err.Error()})
						break
					}

				} else {
					if address, err := net.ResolveUDPAddr("udp", client); err == nil {
						if _, err := sources[ctx.source].pconn.WriteTo(packet, address); err != nil {
							logger.Warn(map[string]any{"event": "reply", "reason": err.Error()})
							break
						}

					} else {
						logger.Warn(map[string]any{"event": "reply", "reason": err.Error()})
						break
					}
				}
				hostname := j.String(frame["hostname"])
				if value := j.String(frame["domain-name"]); value != "" {
					hostname += "." + value
				}
				logger.Info(map[string]any{
					"event":     "reply",
					"type":      j.String(frame["dhcp-message-type"]),
					"txid":      j.String(frame["client-hardware-address"]) + "/" + j.String(frame["bootp-transaction-id"]),
					"interface": ctx.source,
					"client":    client,
					"address":   j.String(frame["bootp-assigned-address"]),
					"hostname":  hostname,
					"duration":  ustr.Duration(time.Since(ctx.created)),
				})
				mu.Lock()
				delete(contexts, key)
				mu.Unlock()
			}
		}
	}
}
