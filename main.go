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

	sysctl "github.com/lorenzosaino/go-sysctl"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"
)

var startSrcPort = flag.Int("startSrcPort", 45000, "The base source port to start probing from")
var endSrcPort = flag.Int("endSrcPort", 46000, "The base source port to end probing")
var dstPort = flag.Int("dstPort", 9100, "The destination port for probes")
var srcAddr = flag.String("srcAddr", "", "The source address for probes")
var failuresCount = flag.Int("failuresCount", 100, "Failures count to depreference the peer")
var probeInterval = flag.Duration("probeInterval", time.Second, "Interval between probes")
var dryRun = flag.Bool("dryRun", true, "Dry-run mode")

type Decider struct {
	logger      *zap.Logger
	Neighbors   Neighbors
	Routes      map[string]netlink.Route
	Destination string
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

	if *dryRun {
		return err
	}

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

	if *dryRun {
		return err
	}

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

func (n *Neighbor) failed() bool {
	return n.Failures > *failuresCount
}

func (d *Decider) createRoute(nr netlink.Route) error {
	return netlink.RouteReplace(&nr)
}

func (d *Decider) undrainAll() error {
	var err error

	for _, neighbor := range d.Neighbors {
		if err := neighbor.undrain(); err != nil {
			return err
		}
	}

	d.removeAllRoutes()

	return err
}

func (d *Decider) removeAllRoutes() {
	if *dryRun {
		return
	}

	for _, route := range d.Routes {
		_ = netlink.RouteDel(&route)
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

func (d *Decider) Run() {
	for _, neighbor := range d.Neighbors {
		nr := d.Routes[neighbor.RemoteIP]
		if err := d.createRoute(nr); err != nil {
			d.logger.Error("unable to create static route", zap.Error(err))
		}

		sPort := *startSrcPort
		for !neighbor.failed() && sPort < *endSrcPort {
			d.logger.Debug("Probing connection",
				zap.String("Destination", d.Destination),
				zap.String("Source", *srcAddr),
				zap.String("Via", neighbor.RemoteIP),
				zap.Int("Failures", neighbor.Failures),
				zap.Int("SourcePort", sPort))

			conn, err := net.DialTCP("tcp", &net.TCPAddr{
				IP:   net.ParseIP("0.0.0.0"),
				Port: sPort,
			}, &net.TCPAddr{
				IP:   net.ParseIP(d.Destination),
				Port: *dstPort,
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
				zap.String("Destination", d.Destination),
				zap.String("Source", *srcAddr),
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

func newDecider(dst string) (*Decider, error) {
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

	d := &Decider{
		logger:      logger,
		Neighbors:   Neighbors{},
		Routes:      make(map[string]netlink.Route),
		Destination: dst,
	}

	neighbors, err := getNeighbors()
	if err != nil {
		return d, err
	}
	if len(neighbors) == 0 {
		return d, errors.New("no BGP neighbors")
	}
	d.Neighbors = neighbors

	d.Routes = createRoutes(neighbors, dst)

	return d, nil
}

func createRoutes(neighbors Neighbors, dst string) map[string]netlink.Route {
	routes := make(map[string]netlink.Route)
	src := *srcAddr

	for _, neighbor := range neighbors {
		if len(*srcAddr) == 0 {
			src = neighbor.LocalIP
		}
		nr := netlink.Route{
			Dst: &net.IPNet{
				IP:   net.ParseIP(dst),
				Mask: net.IPv4Mask(255, 255, 255, 255),
			},
			Src:      net.ParseIP(src),
			Protocol: unix.RTPROT_KERNEL,
			Table:    unix.RT_TABLE_MAIN,
			Type:     unix.RTN_UNICAST,
			Gw:       net.ParseIP(neighbor.RemoteIP),
		}
		routes[neighbor.RemoteIP] = nr
	}

	return routes
}

func getNeighbors() (Neighbors, error) {
	var neighbors Neighbors

	output, err := exec.Command("vtysh", "-c", "show ip bgp neighbors json").Output()
	if err != nil {
		return nil, errors.New("failed `show ip bgp neighbors json`")
	}

	if err := json.Unmarshal([]byte(output), &neighbors); err != nil {
		return nil, err
	}

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

	d, err := newDecider(dst)
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
		if err := d.undrainAll(); err != nil {
			d.logger.Error("unable to undrain all neighbors", zap.Error(err))
		}
		os.Exit(0)
	}()

	if err := d.undrainAll(); err != nil {
		d.logger.Error("unable to undrain all neighbors", zap.Error(err))
		return
	}

	for {
		d.Run()
		time.Sleep(1 * time.Second)
	}
}
