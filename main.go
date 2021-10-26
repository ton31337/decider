package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lorenzosaino/go-sysctl"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"
)

var startSrcPort = flag.Int("startSrcPort", 45000, "The base source port to start probing from")
var endSrcPort = flag.Int("endSrcPort", 46000, "The base source port to end probing")
var failuresCount = flag.Int("failuresCount", 100, "Failures count to depreference the peer")
var probeInterval = flag.Duration("probeInterval", time.Second, "Interval between probes")
var dryRun = flag.Bool("dryRun", true, "Dry-run mode")

type Decider struct {
	logger    *zap.Logger
	Neighbors Neighbors
}

type Neighbors map[string]struct {
	Neighbor
}

type IPv4Unicast struct {
	RouteMapIncoming string `json:"routeMapForIncomingAdvertisements"`
	RouteMapOutgoing string `json:"routeMapForOutgoingAdvertisements"`
}

type Neighbor struct {
	RemoteAS int    `json:"remoteAs"`
	LocalAS  int    `json:"localAs"`
	State    string `json:"bgpState"`
	LocalIP  string `json:"hostLocal"`
	RemoteIP string `json:"hostForeign"`
	Af       struct {
		IPv4Unicast    *IPv4Unicast `json:"ipv4Unicast"`
		IPv4UnicastOld *IPv4Unicast `json:"IPv4 Unicast"`
	} `json:"addressFamilyInfo"`
	Failures int
}

func (n *Neighbor) IPv4Unicast() IPv4Unicast {
	if n.Af.IPv4Unicast == nil {
		return *n.Af.IPv4UnicastOld
	}
	return *n.Af.IPv4Unicast
}

func (n Neighbor) RouteMapIncoming() string {
	return n.IPv4Unicast().RouteMapIncoming
}

func (n Neighbor) RouteMapOutgoing() string {
	return n.IPv4Unicast().RouteMapOutgoing
}

func (n *Neighbor) drain() error {
	var err error

	err = exec.Command(
		"vtysh", "-c",
		"configure terminal", "-c",
		"route-map "+n.RouteMapOutgoing()+" permit 1", "-c",
		"set as-path prepend 47583 47583", "-c",
		"on-match next",
	).Run()

	if err != nil {
		return err
	}

	err = exec.Command(
		"vtysh", "-c",
		"configure terminal", "-c",
		"route-map "+n.RouteMapIncoming()+" permit 1", "-c",
		"set local-preference 50", "-c",
		"on-match next",
	).Run()

	return err
}

func (n *Neighbor) undrain() error {
	var err error

	err = exec.Command(
		"vtysh", "-c",
		"configure terminal", "-c",
		"no route-map "+n.RouteMapOutgoing()+" permit 1",
	).Run()

	if err != nil {
		return err
	}

	err = exec.Command(
		"vtysh", "-c",
		"configure terminal", "-c",
		"no route-map "+n.RouteMapIncoming()+" permit 1",
	).Run()

	return err
}

func (n *Neighbor) deleteRoute(nr *netlink.Route) {
	netlink.RouteDel(nr)
}

func (n *Neighbor) failed() bool {
	return n.Failures > *failuresCount
}

func (n *Neighbor) createRoute(dst string) error {
	var err error

	if *dryRun {
		return err
	}

	nr := netlink.Route{
		Dst: &net.IPNet{
			IP:   net.ParseIP(dst),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
		Src:      net.ParseIP(n.LocalIP),
		Protocol: unix.RTPROT_KERNEL,
		Table:    unix.RT_TABLE_MAIN,
		Type:     unix.RTN_UNICAST,
		Gw:       net.ParseIP(n.RemoteIP),
	}

	err = netlink.RouteReplace(&nr)
	if err != nil {
		n.deleteRoute(&nr)
	}

	return err
}

func (d *Decider) undrainAll() {
	for _, neighbor := range d.Neighbors {
		neighbor.undrain()
	}
}

func (d *Decider) allNeighborsFailed() bool {
	var count int

	for _, neighbor := range d.Neighbors {
		if neighbor.failed() {
			count++
		}
	}

	if len(d.Neighbors) == 1 {
		return false
	}

	return count == len(d.Neighbors)
}

func (d *Decider) Run(dst string) {
	for _, neighbor := range d.Neighbors {
		if err := neighbor.createRoute(dst); err != nil {
			d.logger.Error("unable to create static route", zap.Error(err), zap.Any("Destination", dst))
		}

		sPort := *startSrcPort
		for !neighbor.failed() && sPort < *endSrcPort {
			d.logger.Debug("Probing connection",
				zap.String("Destination", dst),
				zap.String("Source", neighbor.LocalIP),
				zap.String("Via", neighbor.RemoteIP),
				zap.Int("Failures", neighbor.Failures),
				zap.Int("SourcePort", sPort))

			conn, err := net.DialTCP("tcp", &net.TCPAddr{
				IP:   net.ParseIP("0.0.0.0"),
				Port: sPort,
			}, &net.TCPAddr{
				IP:   net.ParseIP(dst),
				Port: 9100,
			})
			if err != nil {
				d.logger.Error("unable to create TCP connection", zap.Error(err),
					zap.Any("Connection", conn))
				neighbor.Failures++
				sPort++
				continue
			}
			defer conn.Close()

			_, err = conn.Write([]byte("PING"))
			if err != nil {
				d.logger.Error("unable to send data to destination", zap.Error(err),
					zap.Any("Connection", conn))
				neighbor.Failures++
				sPort++
				continue
			}

			conn.Close()

			d.logger.Debug("Successful connection",
				zap.String("Destination", dst),
				zap.String("Source", neighbor.LocalIP),
				zap.String("Via", neighbor.RemoteIP),
				zap.Int("SourcePort", sPort))
			sPort++
			time.Sleep(*probeInterval)
		}
		if neighbor.failed() && !d.allNeighborsFailed() {
			d.logger.Warn("Draining traffic",
				zap.String("Neighbor", neighbor.RemoteIP),
				zap.String("RouteMapIncoming", neighbor.RouteMapIncoming()),
				zap.String("RouteMapOutgoing", neighbor.RouteMapOutgoing()))
			if *dryRun {
				continue
			}
			if err := neighbor.drain(); err != nil {
				d.logger.Error("unable to drain", zap.Error(err))
			}
		} else {
			d.logger.Warn("Undraining traffic",
				zap.String("Neighbor", neighbor.RemoteIP),
				zap.String("RouteMapIncoming", neighbor.RouteMapIncoming()),
				zap.String("RouteMapOutgoing", neighbor.RouteMapOutgoing()))
			if *dryRun {
				continue
			}
			if err := neighbor.undrain(); err != nil {
				d.logger.Error("unable to undrain", zap.Error(err))
			}
		}
	}
}

func newDecider() (*Decider, error) {
	logger, _ := zap.Config{
		Encoding:    "json",
		Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
		OutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:    "timestamp",
			EncodeTime: zapcore.ISO8601TimeEncoder,
			MessageKey: "message",
		},
	}.Build()

	s := &Decider{
		logger:    logger,
		Neighbors: Neighbors{},
	}

	neighbors, err := getNeighbors()
	if err != nil {
		return s, errors.New("can't fetch BGP neighbors")
	}

	if len(neighbors) == 0 {
		return s, errors.New("no BGP neighbors")
	}

	s.Neighbors = neighbors

	return s, nil
}

func getNeighbors() (Neighbors, error) {
	var neighbors Neighbors

	output, err := exec.Command("vtysh", "-c", "show ip bgp neighbors json").Output()
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(output), &neighbors)

	for neighbor, params := range neighbors {
		if (params.RemoteAS >= 64512 && params.RemoteAS <= 65534) ||
			(params.RemoteAS >= 4200000000 && params.RemoteAS <= 4294967294) ||
			strings.Contains(neighbor, "swp") ||
			strings.Contains(neighbor, ":") ||
			params.State != "Established" {
			delete(neighbors, neighbor)
		}
	}

	return neighbors, nil
}

func main() {
	flag.Parse()
	if flag.Arg(0) == "" {
		fmt.Fprintf(os.Stderr, "Destination IP is missing\n")
		return
	}
	dst := flag.Arg(0)

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	d, err := newDecider()
	if err != nil {
		d.logger.Error("unable to create Decider object", zap.Error(err))
		return
	}

	err = sysctl.Set("net.ipv4.tcp_syn_retries", "2")
	if err != nil {
		d.logger.Error("unable to set sysctl (net.ipv4.tcp_syn_retries)", zap.Error(err))
		return
	}

	local_reserved_ports := fmt.Sprintf("%d-%d", *startSrcPort, *endSrcPort)
	err = sysctl.Set("net.ipv4.ip_local_reserved_ports", local_reserved_ports)
	if err != nil {
		d.logger.Error("unable to set sysctl (net.ipv4.ip_local_reserved_ports)", zap.Error(err))
		return
	}

	go func() {
		<-c
		d.undrainAll()
		os.Exit(0)
	}()

	d.undrainAll()
	for {
		d.Run(dst)
		time.Sleep(1 * time.Second)
	}
}
