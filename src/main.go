package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/fqdn"
	"github.com/pyke369/golang-support/ulog"
	"golang.org/x/sys/unix"
)

const progname = "pdhcp"
const version = "2.0.3"

type SOURCE struct {
	mode    string
	rhandle *RawConn
	handle  net.PacketConn
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

var (
	log      *ulog.ULog
	sources  = map[string]*SOURCE{}
	contexts = map[string]*CONTEXT{}
	lock     sync.RWMutex
)

// abort program with an error message
func bail(message interface{}) {
	fmt.Fprintf(os.Stderr, "%v - aborting\n", message)
	os.Exit(1)
}

// main program entry
func main() {
	var arguments flag.FlagSet

	// parse command-line arguments
	arguments = flag.FlagSet{Usage: func() {
		fmt.Fprintf(os.Stderr, "usage: %s [OPTIONS...]\n\noptions are:\n", filepath.Base(os.Args[0]))
		arguments.PrintDefaults()
	},
	}
	help := arguments.Bool("h", false, "show this help screen")
	sversion := arguments.Bool("v", false, "show the program version")
	list1 := arguments.Bool("l", false, "list all available DHCP options (human format)")
	list2 := arguments.Bool("j", false, "list all available DHCP options (JSON format)")
	v6 := arguments.Bool("6", false, "run in IPv6 mode")
	interfaces := arguments.String("i", "", "specify a comma-separated list of interfaces to use")
	backend := arguments.String("b", "", "specify the backend command path or URL")
	workers := arguments.Int("w", 1, "change the backend workers count")
	relay := arguments.String("r", "", "specify the remote DHCP server address in relay mode")
	arelay := arguments.String("s", "", "use an alternate local relay address")
	extra := arguments.String("R", "", "add/modify DHCP attributes in the default client request")
	address := arguments.String("a", "0.0.0.0", "use an alternate listen address")
	port := arguments.Int("p", 67, "use an alternate DHCP port")
	format := arguments.String("f", "", "provide an alternate logging configuration")
	if err := arguments.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	mode := "client"
	if *backend != "" {
		mode = "backend"
	} else if *relay != "" {
		mode = "relay"
	}
	if _, _, err := net.SplitHostPort(*relay); err != nil {
		*relay += ":67"
	}

	// IPv6 mode
	if *v6 {
		bail("IPv6 mode is not implemented yet")
	}

	// show help screen
	if *help {
		arguments.Usage()
		os.Exit(0)
	}

	// show program version
	if *sversion {
		fmt.Printf("%s/v%s\n", progname, version)
		os.Exit(0)
	}

	// show available DHCP attributes
	if *list1 || *list2 {
		v4options(*list2)
		os.Exit(0)
	}

	// initialize logger
	if *format == "" {
		*format = "console(output=stderr,time=msdatetime) syslog(facility=local0)"
	}
	log = ulog.New(*format)
	if mode != "client" {
		log.Info(map[string]interface{}{"mode": mode, "event": "start", "version": version, "pid": os.Getpid()})
	}

	// start and keep backend workers alive
	pmux, bsink := make(chan PACKET, 1024), make(chan FRAME, 1024)
	if mode == "backend" {
		if strings.HasPrefix(*backend, "http") {
			go func() {
				for {
					select {
					case frame := <-bsink:
						go func(frame FRAME) {
							if payload, err := json.Marshal(frame); err == nil {
								payload = append(payload, '\n')
								if request, err := http.NewRequest(http.MethodPost, *backend, bytes.NewBuffer(payload)); err == nil {
									request.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
									request.Header.Set("Content-Type", "application/json")
									request.Header.Set("User-Agent", fmt.Sprintf("%s/%s", progname, version))
									log.Info(map[string]interface{}{"event": "http-send", "message": fmt.Sprintf("dhcp-%v", frame["dhcp-message-type"]),
										"txid": fmt.Sprintf("%v/%v", frame["client-hardware-address"], frame["bootp-transaction-id"]), "target": *backend})
									client := &http.Client{Timeout: 7 * time.Second}
									if response, err := client.Do(request); err == nil {
										payload, _ := ioutil.ReadAll(response.Body)
										response.Body.Close()

										var frame FRAME
										if err := json.Unmarshal(payload, &frame); err == nil {
											lock.RLock()
											if contexts[v4key(frame)] != nil {
												if packet, err := v4build(frame); err == nil {
													log.Info(map[string]interface{}{"event": "http-receive", "message": fmt.Sprintf("dhcp-%v", frame["dhcp-message-type"]),
														"txid": fmt.Sprintf("%v/%v", frame["client-hardware-address"], frame["bootp-transaction-id"]), "target": *backend})
													pmux <- PACKET{source: "http", client: *backend, data: packet}
												}
											}
											lock.RUnlock()
										}
									}
								}
							}
						}(frame)
					}
				}
			}()
		} else {
			*workers = int(math.Min(16, math.Max(1, float64(*workers))))
			for *workers > 0 {
				go func() {
					for {
						command, pid := &exec.Cmd{Path: *backend}, 0
						if stdin, err := command.StdinPipe(); err == nil {
							if stdout, err := command.StdoutPipe(); err == nil {
								if err := command.Start(); err == nil {
									pid = command.Process.Pid
									log.Info(map[string]interface{}{"event": "worker-start", "backend": *backend, "worker": pid})
									backend := make(chan FRAME)
									go func() {
										reader := bufio.NewReader(stdout)
										for {
											if line, err := reader.ReadString('\n'); err != nil {
												backend <- nil
												break
											} else {
												var frame FRAME
												if err := json.Unmarshal([]byte(line), &frame); err == nil {
													lock.RLock()
													if contexts[v4key(frame)] != nil {
														backend <- frame
													}
													lock.RUnlock()
												} else {
													command.Process.Kill()
												}
											}
										}
									}()
								loop:
									for {
										select {
										case frame := <-bsink:
											if payload, err := json.Marshal(frame); err == nil {
												payload = append(payload, '\n')
												if _, err := stdin.Write(payload); err == nil {
													log.Info(map[string]interface{}{"event": "worker-send", "message": fmt.Sprintf("dhcp-%v", frame["dhcp-message-type"]),
														"txid": fmt.Sprintf("%v/%v", frame["client-hardware-address"], frame["bootp-transaction-id"]), "worker": pid})
												}
											}

										case frame := <-backend:
											if frame == nil {
												break loop
											}
											if packet, err := v4build(frame); err == nil {
												log.Info(map[string]interface{}{"event": "worker-receive", "message": fmt.Sprintf("dhcp-%v", frame["dhcp-message-type"]),
													"txid": fmt.Sprintf("%v/%v", frame["client-hardware-address"], frame["bootp-transaction-id"]), "worker": pid})
												pmux <- PACKET{source: "worker", client: fmt.Sprintf("%d", pid), data: packet}
											}
										}
									}
								}
							}
						}
						log.Warn(map[string]interface{}{"event": "worker-stop", "backend": *backend, "worker": pid, "status": fmt.Sprintf("%v", command.Wait())})
						time.Sleep(5 * time.Second)
					}
				}()
				*workers--
			}
		}
	}

	// client mode: send DHCP request and await server response
	if mode == "client" {
		if *interfaces == "" {
			bail("an interface needs to be specified in client mode")
		}

		handle, err := NewRawConn(&RawAddr{Port: *port + 1, Device: *interfaces})
		if err != nil {
			bail(err)
		}
		for try := 1; try <= 5; try++ {
			txid := rand.Uint32()
			frame := map[string]interface{}{
				"bootp-transaction-id":    fmt.Sprintf("%08x", txid),
				"bootp-broadcast":         true,
				"dhcp-message-type":       "discover",
				"client-hardware-address": handle.Local.HardwareAddr.String(),
				"parameters-request-list": []interface{}{"hostname", "subnet-mask", "routers", "domain-name", "domain-name-servers", "time-offset", "ntp-servers"},
			}
			if handle.Local.Addr != nil {
				frame["requested-ip-address"] = handle.Local.Addr.String()
			}
			hostname, _ := fqdn.FQDN()
			if hostname != "" && hostname != "unknown" {
				frame["hostname"] = hostname
			}
			if *extra != "" {
				var eframe map[string]interface{}
				if err := json.Unmarshal([]byte(*extra), &eframe); err != nil {
					bail(err)
				}
				for name, value := range eframe {
					frame[name] = value
				}
			}
			from, to := &RawAddr{}, &RawAddr{Port: *port}
			if value, ok := frame["bootp-client-address"].(string); ok {
				from.Addr = net.ParseIP(value)
			}
			if packet, err := v4build(frame); err == nil {
				if _, err := handle.WriteTo(from, to, packet); err == nil {
					handle.SetReadDeadline(time.Now().Add(time.Duration(try) * time.Second))
					packet := make([]byte, 4<<10)
					if read, _, err := handle.ReadFrom(packet); err == nil {
						if rframe, err := v4parse(packet[:read]); err == nil {
							if rframe["bootp-opcode"] == "reply" &&
								rframe["client-hardware-address"] == frame["client-hardware-address"] &&
								rframe["bootp-transaction-id"] == frame["bootp-transaction-id"] {
								if mrequest, ok := frame["dhcp-message-type"].(string); ok {
									if mresponse, ok := rframe["dhcp-message-type"].(string); ok {
										if response := V4MSGTYPES[V4RMSGTYPES[mresponse]]; response != nil &&
											(response.request == 0 || response.request == V4RMSGTYPES[mrequest]) {
											if content, err := json.Marshal(rframe); err == nil {
												fmt.Printf("%s\n", content)
												os.Exit(0)
											} else {
												bail(err)
											}
										}
									}
								}
							}
						}
					}
				} else {
					bail(err)
				}
			} else {
				bail(err)
			}
		}
		bail("no response from server")

		// server or relay mode
	} else {
		// create all packets sources
		interfaces := strings.Trim(*interfaces, ",")
		if interfaces != "" {
			interfaces += ","
		}
		for _, name := range strings.Split(interfaces, ",") {
			go func(name string) {
				source := &SOURCE{}
				if name != "" {
					if handle, err := NewRawConn(&RawAddr{Port: *port, Device: name}); err == nil {
						if handle.Local.Addr == nil {
							log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("skipping interface %s: no ip address", name)})
							return
						}
						source.rhandle = handle
						log.Info(map[string]interface{}{"event": "listen", "listen": fmt.Sprintf("%s@%s:%d", name, *address, *port),
							"source": fmt.Sprintf("%s@%s", handle.Local.HardwareAddr, handle.Local.Addr)})
					} else if mode == "relay" {
						config := net.ListenConfig{
							Control: func(network, address string, connection syscall.RawConn) error {
								connection.Control(func(handle uintptr) {
									syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
									syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
									BindToDevice(int(handle), name)
								})
								return nil
							}}
						if handle, err := config.ListenPacket(context.Background(), "udp", fmt.Sprintf("%s:%d", *address, *port)); err == nil {
							source.handle = handle
							log.Info(map[string]interface{}{"event": "listen", "listen": fmt.Sprintf("%s@%s:%d", name, *address, *port)})
						} else {
							log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("skipping interface %s: %v", name, err)})
							return
						}
					} else {
						log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("skipping interface %s: %v", name, err)})
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
					if handle, err := config.ListenPacket(context.Background(), "udp", fmt.Sprintf("%s:%d", *address, *port)); err == nil {
						source.handle = handle
						log.Info(map[string]interface{}{"event": "listen", "listen": fmt.Sprintf("%s@%s:%d", name, *address, *port)})
					} else {
						log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("%v", err)})
						return
					}
				}
				lock.Lock()
				sources[name] = source
				lock.Unlock()
				for {
					packet := [4 << 10]byte{}
					if source.rhandle != nil {
						if read, from, err := source.rhandle.ReadFrom(packet[:]); err == nil {
							pmux <- PACKET{source: name, hardware: from.HardwareAddr.String(), client: fmt.Sprintf("%s:%d", from.Addr.String(), from.Port), data: packet[:read]}
						}
					} else {
						if read, from, err := source.handle.ReadFrom(packet[:]); err == nil {
							pmux <- PACKET{source: name, client: from.String(), data: packet[:read]}
						}
					}
				}
			}(name)
		}

		// expire orphaned contexts
		go func() {
			for {
				now := time.Now()
				lock.Lock()
				for key, context := range contexts {
					if now.Sub(context.created) >= 10*time.Second {
						delete(contexts, key)
					}
				}
				lock.Unlock()
				time.Sleep(time.Second)
			}
		}()

		// run packets muxer on main goroutine
		for {
			select {
			case packet := <-pmux:
				if frame, err := v4parse(packet.data); err != nil {
					log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("%v", err), "source": packet.source, "client": packet.client})
				} else {
					key := v4key(frame)
					if frame["bootp-opcode"] == "request" {
						if _, ok := frame["bootp-relay-address"].(string); ok {
							if packet.source != "-" {
								continue
							}
						} else if packet.source == "-" {
							continue
						} else if value, ok := frame["bootp-client-address"].(string); ok {
							if host, _, err := net.SplitHostPort(packet.client); err == nil && value != host {
								continue
							}
						}
						if value, ok := frame["server-identifier"].(string); ok && sources[packet.source].rhandle != nil {
							if value != sources[packet.source].rhandle.Local.Addr.String() {
								continue
							}
						}
						if value, ok := frame["client-hardware-address"].(string); ok && packet.hardware != "" && packet.hardware != value {
							continue
						}
						lock.Lock()
						if contexts[key] != nil {
							lock.Unlock()
							break
						}
						contexts[key] = &CONTEXT{time.Now(), packet.source, packet.client, frame}
						lock.Unlock()
						address, hostname := "", ""
						if value, ok := frame["requested-ip-address"].(string); ok {
							address = value
						}
						if value, ok := frame["hostname"].(string); ok {
							hostname = value
						}
						log.Info(map[string]interface{}{"event": "request", "message": fmt.Sprintf("dhcp-%v", frame["dhcp-message-type"]),
							"txid":   fmt.Sprintf("%v/%v", frame["client-hardware-address"], frame["bootp-transaction-id"]),
							"source": packet.source, "client": packet.client, "requested-ip-address": address, "hostname": hostname,
						})
						if mode == "relay" {
							rframe, _ := v4parse(packet.data)
							hops := 0
							if value, ok := rframe["bootp-hops"].(int); ok {
								hops = value
							}
							rframe["bootp-relay-hops"] = hops + 1
							if *arelay != "" {
								rframe["bootp-relay-address"] = *arelay
							} else {
								rframe["bootp-relay-address"] = sources[packet.source].rhandle.Local.Addr.String()
							}
							delete(rframe, "bootp-broadcast")
							if rpacket, err := v4build(rframe); err == nil {
								if raddress, err := net.ResolveUDPAddr("udp", *relay); err == nil {
									if _, err := sources["-"].handle.WriteTo(rpacket, raddress); err == nil {
										log.Info(map[string]interface{}{"event": "relay-send", "message": fmt.Sprintf("dhcp-%v", rframe["dhcp-message-type"]),
											"txid": fmt.Sprintf("%v/%v", rframe["client-hardware-address"], rframe["bootp-transaction-id"]), "relay": relay})
									}
								}
							}

						} else {
							if sources[packet.source].rhandle != nil {
								frame["source-address"] = sources[packet.source].rhandle.Local.Addr.String()
							}
							select {
							case bsink <- frame:
							default:
							}
						}

					} else {
						lock.RLock()
						context := contexts[key]
						lock.RUnlock()
						if context == nil {
							break
						}
						client := context.client
						if address, port, err := net.SplitHostPort(context.client); err == nil {
							if value, ok := context.data["bootp-broadcast"].(bool); (ok && value) || net.ParseIP(address).Equal(net.IPv4zero) {
								client = fmt.Sprintf("%s:%s", net.IPv4bcast, port)
								frame["bootp-broadcast"] = value
							}
							if value, ok := context.data["bootp-relay-address"].(string); ok && value != "" {
								client = fmt.Sprintf("%s:%s", value, port)
								frame["bootp-relay-address"] = value
							}
						} else {
							break
						}
						if mode == "relay" {
							log.Info(map[string]interface{}{"event": "relay-receive", "message": fmt.Sprintf("dhcp-%v", frame["dhcp-message-type"]),
								"txid": fmt.Sprintf("%s/%s", frame["client-hardware-address"], frame["bootp-transaction-id"]), "relay": relay})
						}
						if sources[context.source].rhandle != nil && sources[context.source].rhandle.Local.Addr != nil {
							frame["server-identifier"] = sources[context.source].rhandle.Local.Addr.String()
						}
						packet, _ := v4build(frame)
						if sources[context.source].rhandle != nil {
							if address, value, err := net.SplitHostPort(client); err == nil {
								port, _ := strconv.Atoi(value)
								to := &RawAddr{Addr: net.ParseIP(address), Port: port}
								if !to.Addr.Equal(net.IPv4bcast) && !to.Addr.Equal(net.IPv6linklocalallrouters) {
									to.HardwareAddr, _ = net.ParseMAC(frame["client-hardware-address"].(string))
								}
								if _, err := sources[context.source].rhandle.WriteTo(nil, to, packet); err != nil {
									log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("%v", err)})
									break
								}
							} else {
								log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("%v", err)})
								break
							}
						} else {
							if address, err := net.ResolveUDPAddr("udp", client); err == nil {
								if _, err := sources[context.source].handle.WriteTo(packet, address); err != nil {
									log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("%v", err)})
									break
								}
							} else {
								log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("%v", err)})
								break
							}
						}
						address, hostname := "", ""
						if value, ok := frame["bootp-assigned-address"].(string); ok {
							address = value
						}
						if value, ok := frame["hostname"].(string); ok {
							hostname = value
							if value, ok := frame["domain-name"].(string); ok {
								hostname += "." + value
							}
						}
						log.Info(map[string]interface{}{"event": "reply", "message": fmt.Sprintf("dhcp-%v", frame["dhcp-message-type"]),
							"txid":   fmt.Sprintf("%s/%s", frame["client-hardware-address"], frame["bootp-transaction-id"]),
							"source": context.source, "client": client, "bootp-assigned-address": address, "hostname": hostname,
							"duration": fmt.Sprintf("%.2fms", float64(time.Now().Sub(context.created))/float64(time.Millisecond))})
						lock.Lock()
						delete(contexts, key)
						lock.Unlock()
					}
				}
			}
		}
	}
}
