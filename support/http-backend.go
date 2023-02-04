package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/dynacert"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
)

const progname = "http-backend"
const version = "2.0.0"

type LEASE struct {
	Client   string `json:"client"`
	State    string `json:"state"`
	Deadline int64  `json:"deadline"`
	Renewed  int64  `json:"renewed"`
}

var (
	config    *uconfig.UConfig
	log, alog *ulog.ULog
	leases    = map[string]LEASE{}
	lock      sync.RWMutex
)

func please(request map[string]interface{}, duration int64, first, last net.IP) (output string) {
	client, start, end, caddress, raddress := "", binary.BigEndian.Uint32(first), binary.BigEndian.Uint32(last), "", ""
	if value, ok := request["client-hardware-address"].(string); ok {
		client = value
	} else {
		return
	}
	if value, ok := request["dhcp-message-type"].(string); ok && value == "request" {
		if value, ok := request["bootp-client-address"].(string); ok {
			if address := net.ParseIP(value); address != nil && address.To4() != nil {
				if index := binary.BigEndian.Uint32(address.To4()); index >= start && index <= end {
					caddress = value
				}
			}
		}
		if value, ok := request["requested-ip-address"].(string); ok {
			if address := net.ParseIP(value); address != nil && address.To4() != nil {
				if index := binary.BigEndian.Uint32(address.To4()); index >= start && index <= end {
					raddress = value
				}
			}
		}
	}
	lock.Lock()
	for index := start; index <= end; index++ {
		address := net.IPv4(byte(index>>24), byte(index>>16), byte(index>>8), byte(index)).String()
		if lease, ok := leases[address]; ok && lease.Client == client {
			if caddress != "" {
				if caddress == address && lease.State == "lease" {
					output = address
					lease.Renewed = time.Now().Unix()
					lease.Deadline = lease.Renewed + duration
				}
			} else {
				output = address
				if raddress != "" && raddress == address && lease.State == "prelease" {
					lease.State = "lease"
					lease.Deadline = time.Now().Add(time.Duration(duration) * time.Second).Unix()
				}
			}
			leases[address] = lease
			break
		}
	}
	if output == "" && caddress == "" && raddress == "" {
		for index := start; index <= end; index++ {
			address := net.IPv4(byte(index>>24), byte(index>>16), byte(index>>8), byte(index)).String()
			if _, ok := leases[address]; !ok {
				leases[address] = LEASE{Client: client, State: "prelease", Deadline: time.Now().Add(10 * time.Second).Unix()}
				output = address
				break
			}
		}
	}
	lock.Unlock()
	return
}

func assign(input map[string]interface{}, request map[string]interface{}, key, value string) (output map[string]interface{}) {
	output = input
	if matcher := rcache.Get(`^(array|dup|drop|lease)\((.*?)\)$`); matcher != nil && matcher.MatchString(value) {
		matches := matcher.FindStringSubmatch(value)
		switch matches[1] {
		case "array":
			output[key] = strings.Split(matches[2], "|")
		case "dup":
			if value, ok := request[matches[2]]; ok {
				output[key] = value
			}
		case "drop":
			delete(output, key)
		case "lease":
			for _, arange := range strings.Split(matches[2], "|") {
				if parts := strings.Split(strings.TrimSpace(arange), "-"); len(parts) == 2 {
					if first := net.ParseIP(strings.TrimSpace(parts[0])); first != nil && first.To4() != nil {
						if last := net.ParseIP(strings.TrimSpace(parts[1])); last != nil && last.To4() != nil {
							duration, _ := strconv.Atoi(fmt.Sprintf("%v", input["address-lease-time"]))
							if duration == 0 {
								duration = 86400
							}
							if value := please(request, int64(duration), first.To4(), last.To4()); value != "" {
								output[key] = value
								break
							}
						}
					}
				}
			}
		}
	} else {
		output[key] = value
	}
	return output
}

func build(input map[string]interface{}, request map[string]interface{}, path string) (output map[string]interface{}) {
	output = input
	if output == nil {
		output = map[string]interface{}{}
	}
	if request == nil {
		return output
	}
	sections := []string{}
	for _, section := range config.GetPaths(path) {
		if len(config.GetPaths(section+".match")) > 0 {
			sections = append(sections, section)
		} else {
			sections = append(sections, "!"+section)
		}
	}
	sort.Strings(sections)
	for index, section := range sections {
		sections[index] = strings.TrimPrefix(section, "!")
	}
	for _, section := range sections {
		if matches := config.GetPaths(section + ".match"); len(matches) > 0 {
			matched := true
			for _, match := range matches {
				rvalue, mvalue, negate, regex := "", strings.TrimSpace(config.GetString(match, "")), false, false
				if value, ok := request[strings.TrimPrefix(match, section+".match.")]; ok {
					rvalue = fmt.Sprintf("%v", value)
				}
				if len(mvalue) > 0 && mvalue[0] == '!' {
					negate = true
					mvalue = strings.TrimSpace(mvalue[1:])
				}
				if len(mvalue) > 0 && mvalue[0] == '~' {
					regex = true
					mvalue = strings.TrimSpace(mvalue[1:])
				}
				if regex {
					if matcher := rcache.Get(mvalue); matcher != nil {
						if matcher.MatchString(rvalue) {
							if negate {
								matched = false
							}
						} else {
							if !negate {
								matched = false
							}
						}
					} else {
						if !negate {
							matched = false
						}
					}
				} else {
					if rvalue == mvalue {
						if negate {
							matched = false
						}
					} else {
						if !negate {
							matched = false
						}
					}
				}
			}
			if !matched {
				continue
			}
		}
		if !strings.HasSuffix(section, ".match") {
			if paths := config.GetPaths(section); len(paths) > 0 {
				if strings.HasSuffix(paths[0], ".0") {
					values := []string{}
					for _, path := range paths {
						values = append(values, strings.ReplaceAll(config.GetString(path, ""), "|", ""))
					}
					output = assign(output, request, strings.TrimPrefix(section, path+"."), "array("+strings.Join(values, "|")+")")
				} else {
					output = build(output, request, section)
				}
			} else if value := config.GetString(section, ""); value != "" {
				output = assign(output, request, strings.TrimPrefix(section, path+"."), value)
			}
		}
	}
	return output
}

func handler(response http.ResponseWriter, request *http.Request) {
	var frame map[string]interface{}

	if request.Method == http.MethodGet && request.URL.Path == "/leases" {
		// TODO add IP/credentials-based ACL check
		lock.RLock()
		if content, err := json.Marshal(leases); err != nil {
			response.WriteHeader(http.StatusInternalServerError)
		} else {
			response.Header().Set("Content-Type", "application/json")
			response.Write(content)
		}
		lock.RUnlock()
		return
	}
	if request.Method != http.MethodPost {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if body, err := ioutil.ReadAll(request.Body); err != nil {
		response.WriteHeader(http.StatusUnprocessableEntity)
	} else {
		if err := json.Unmarshal(body, &frame); err != nil {
			response.WriteHeader(http.StatusUnprocessableEntity)
		} else {
			alog.Info(frame)
			if _, ok := frame["dhcp-message-type"].(string); !ok {
				response.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if rframe := build(nil, frame, "rules"); rframe == nil {
				response.WriteHeader(http.StatusInternalServerError)
			} else {
				if _, ok := rframe["dhcp-message-type"].(string); !ok {
					response.WriteHeader(http.StatusNotFound)
					return
				}
				if value, ok := rframe["bootp-assigned-address"].(string); ok {
					if net.ParseIP(value) == nil {
						delete(rframe, "bootp-assigned-address")
						if addresses, err := net.LookupHost(value); err == nil && len(addresses) > 0 {
							value, rframe["bootp-assigned-address"] = addresses[0], addresses[0]
						}
					}
					if names, err := net.LookupAddr(value); err == nil {
						if parts := strings.Split(names[0], "."); len(parts) > 0 {
							if _, ok := rframe["hostname"]; !ok {
								rframe["hostname"] = parts[0]
								if len(parts) > 1 {
									rframe["domain-name"] = strings.Trim(strings.Join(parts[1:], "."), ".")
								}
							}
						}
					}
				}
				if _, ok := rframe["bootp-assigned-address"]; !ok {
					log.Warn(map[string]interface{}{"event": "error", "error": fmt.Sprintf("cannot assign address to %v", frame["client-hardware-address"])})
					response.WriteHeader(http.StatusNotFound)
					return
				}
				alog.Info(rframe)
				if payload, err := json.Marshal(rframe); err != nil {
					response.WriteHeader(http.StatusInternalServerError)
				} else {
					response.Header().Set("Content-Type", "application/json")
					response.Write(payload)
				}
			}
		}
	}
}

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configuration file>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	if config, err = uconfig.New(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration file syntax error: %s - aborting\n", err)
		os.Exit(2)
	}
	log = ulog.New(config.GetString("backend.log", "console(output=stdout)"))
	log.Info(map[string]interface{}{"event": "start", "config": os.Args[1], "pid": os.Getpid(), "version": version})
	alog = ulog.New(config.GetString("backend.access", ""))

	if path := config.GetString("backend.leases", ""); path != "" {
		if content, err := ioutil.ReadFile(path); err == nil {
			json.Unmarshal(content, &leases)
		}
	}

	http.HandleFunc("/", handler)
	for _, path := range config.GetPaths("backend.listen") {
		if parts := strings.Split(config.GetStringMatch(path, "_", "^.*?(:\\d+)?((,[^,]+){2})?$"), ","); parts[0] != "_" {
			if len(parts) > 1 {
				certificates := &dynacert.DYNACERT{}
				certificates.Add("*", parts[1], parts[2])
				server := &http.Server{
					Addr:         strings.TrimLeft(parts[0], "*"),
					ReadTimeout:  uconfig.Duration(config.GetDurationBounds("backend.read_timeout", 10, 5, 30)),
					IdleTimeout:  uconfig.Duration(config.GetDurationBounds("backend.idle_timeout", 30, 5, 30)),
					WriteTimeout: uconfig.Duration(config.GetDurationBounds("backend.write_timeout", 15, 5, 30)),
					TLSConfig:    dynacert.IntermediateTLSConfig(certificates.GetCertificate),
					TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
				}
				go func(server *http.Server, parts []string) {
					log.Info(map[string]interface{}{"event": "listen", "listen": parts[0], "public": parts[1], "key": parts[2]})
					for {
						server.ListenAndServeTLS("", "")
						time.Sleep(time.Second)
					}
				}(server, parts)
			} else {
				server := &http.Server{
					Addr:         strings.TrimLeft(parts[0], "*"),
					ReadTimeout:  uconfig.Duration(config.GetDurationBounds("backend.read_timeout", 10, 5, 30)),
					IdleTimeout:  uconfig.Duration(config.GetDurationBounds("backend.idle_timeout", 30, 5, 30)),
					WriteTimeout: uconfig.Duration(config.GetDurationBounds("backend.write_timeout", 15, 5, 30)),
				}
				go func(server *http.Server, parts []string) {
					log.Info(map[string]interface{}{"event": "listen", "listen": parts[0]})
					for {
						server.ListenAndServe()
						time.Sleep(time.Second)
					}
				}(server, parts)
			}
		}
	}

	go func() {
		for range time.Tick(5 * time.Second) {
			if sync := config.GetString("backend.sync", ""); sync != "" {
				client := &http.Client{Timeout: 5 * time.Second}
				if response, err := client.Get(sync); err == nil {
					content, _ := ioutil.ReadAll(response.Body)
					response.Body.Close()
					if response.StatusCode/100 == 2 {
						sleases := map[string]LEASE{}
						if json.Unmarshal(content, &sleases) == nil {
							lock.Lock()
							for address, lease := range sleases {
								leases[address] = lease
							}
							lock.Unlock()
						}
					}
				}
			}
			lock.Lock()
			now := time.Now().Unix()
			for address, lease := range leases {
				if lease.Deadline <= now {
					delete(leases, address)
				}
			}
			lock.Unlock()
			if path := config.GetString("backend.leases", ""); path != "" {
				lock.RLock()
				if content, err := json.Marshal(leases); err == nil {
					ioutil.WriteFile(path, content, 0644)
				}
				lock.RUnlock()
			}
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for {
		signal := <-signals
		switch {
		case signal == syscall.SIGHUP:
			if _, err = uconfig.New(os.Args[1]); err == nil {
				config.Load(os.Args[1])
				log.Load(config.GetString("backend.log", "console(output=stdout)"))
				log.Info(map[string]interface{}{"event": "reload", "config": os.Args[1], "pid": os.Getpid(), "version": version})
				alog.Load(config.GetString("backend.access", ""))
			} else {
				log.Warn(map[string]interface{}{"event": "reload", "config": os.Args[1], "error": fmt.Sprintf("invalid configuration (%v)", err)})
			}
		}
	}
}
