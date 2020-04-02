package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	ListenAddr  = flag.String("listenaddr", ":9509", "ovpnserver_exporter listen address")
	MetricsPath = flag.String("metricspath", "/metrics", "URL path for surfacing collected metrics")
	ovpnlog     = flag.String("ovpn.log", "/var/log/status.log", "Absolute path for OpenVPN server log")
)

var (
	ovpnclientscount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_count",
		Help: "Current OpenVPN logged in users",
	})
	ovpnmaxbcastmcastqueue = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_maxmacatbcastqueue",
		Help: "Current Max Broadcast/Multicast queue",
	})
	ovpnremote = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_remote",
		Help: "OpenVPN users statistics",
	},
		[]string{"client", "ip"},
	)
	ovpnbytesr = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_bytesr",
		Help: "OpenVPN user Bytes Received",
	},
		[]string{"client", "number"},
	)
	ovpnbytess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_bytess",
		Help: "OpenVPN user Bytes Sent",
	},
		[]string{"client", "number"},
	)
	ovpnrouting = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_routing",
		Help: "OpenVPN Routing Table",
	},
		[]string{"record_number", "client", "local_ip", "remote_ip"},
	)
)

const (
	time_layout = "Mon Jan _2 15:04:05 2006"
)

func init() {
	prometheus.MustRegister(ovpnclientscount)
	prometheus.MustRegister(ovpnmaxbcastmcastqueue)
	prometheus.MustRegister(ovpnremote)
	prometheus.MustRegister(ovpnbytesr)
	prometheus.MustRegister(ovpnbytess)
	prometheus.MustRegister(ovpnrouting)
}

type OVPN struct {
	Updated            string   `json:"updated"`
	Clients            []Client `json:"clients"`
	Routing            []Route  `json:"routing"`
	MaxBcastMcastQueue string   `json:"max_bcast_mcast_queue"`
}

type Client struct {
	Client        string `json:"client"`
	Remote        string `json:"remote"`
	BytesReceived string `json:"bytes_received"`
	BytesSent     string `json:"bytes_sent"`
}

type Route struct {
	LocalIP string `json:"local_ip"`
	Client  string `json:"client"`
	RealIP  string `json:"real_ip"`
}

func (ovpn *OVPN) Parse(logfile string) error {
	file, err := os.OpenFile(logfile, os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var section string
	for scanner.Scan() {
		switch section {
		case "":
			if scanner.Text() != "OpenVPN CLIENT LIST" {
				return fmt.Errorf("unknow first line format")
			}
			section = "updated"
			break

		case "updated":
			fields := strings.Split(scanner.Text(), ",")
			if len(fields) != 2 {
				return fmt.Errorf("unknow second line format")
			}
			t, err := time.Parse(time_layout, fields[1])
			if err != nil {
				return fmt.Errorf("parse update time: %s", err)
			}
			ovpn.Updated = t.String()
			section = "client header"
			break

		case "client header":
			fields := strings.Split(scanner.Text(), ",")
			if len(fields) != 5 {
				return fmt.Errorf("parse clients header fields count not eq 5")
			}
			section = "clients"
			break

		case "clients":
			for scanner.Scan() {
				s := scanner.Text()
				if s == "ROUTING TABLE" {
					section = "routing header"
					break
				}
				fields := strings.Split(s, ",")
				if len(fields) != 5 {
					return fmt.Errorf("parse client line %s", s)
				}
				ovpn.Clients = append(
					ovpn.Clients,
					Client{
						Client:        fields[0],
						Remote:        fields[1],
						BytesReceived: fields[2],
						BytesSent:     fields[3],
					})
			}
			break

		case "routing header":
			fields := strings.Split(scanner.Text(), ",")
			if len(fields) != 4 {
				return fmt.Errorf("parse routing header fields count not eq 4")
			}
			section = "routing table"
			break

		case "routing table":
			for scanner.Scan() {
				s := scanner.Text()
				if s == "GLOBAL STATS" {
					section = "global stats"
					break
				}
				fields := strings.Split(s, ",")
				if len(fields) != 4 {
					return fmt.Errorf("parse routing line %s", s)
				}
				ovpn.Routing = append(
					ovpn.Routing,
					Route{
						LocalIP: fields[0],
						Client:  fields[1],
						RealIP:  fields[2],
					})
			}
			break

		case "global stats":
			fields := strings.Split(scanner.Text(), ",")
			if len(fields) != 2 {
				return fmt.Errorf("unknow second line format")
			}
			ovpn.MaxBcastMcastQueue = fields[1]
			section = "end"
			break

		case "end":
			if scanner.Text() != "END" {
				return fmt.Errorf("not find end")
			}
			break
		}
	}
	return scanner.Err()
}

func main() {
	flag.Parse()
	if *ovpnlog == "" {
		log.Fatal("OpenVPN status log absolute path must be set with '-ovpn.log' flag")
	}
	if _, err := os.Stat(*ovpnlog); os.IsNotExist(err) {
		log.Fatal("File: ", *ovpnlog, " does not exists")
	}

	go func() {
		for {
			var ovpn OVPN
			if err := ovpn.Parse(*ovpnlog); err != nil {
				log.Fatal("Parse log: ", err)
			}
			strmcast, _ := strconv.ParseFloat(ovpn.MaxBcastMcastQueue, 64)
			ovpnclientscount.Set(float64(len(ovpn.Clients)))
			ovpnmaxbcastmcastqueue.Set(strmcast)
			for i := range ovpn.Clients {
				bytesr, _ := strconv.Atoi(ovpn.Clients[i].BytesReceived)
				bytess, _ := strconv.Atoi(ovpn.Clients[i].BytesSent)
				ovpnremote.WithLabelValues(ovpn.Clients[i].Client, ovpn.Clients[i].Remote).Set(float64(i + 1))
				ovpnbytesr.WithLabelValues(ovpn.Clients[i].Client, strconv.Itoa(i+1)).Set(float64(bytesr))
				ovpnbytess.WithLabelValues(ovpn.Clients[i].Client, strconv.Itoa(i+1)).Set(float64(bytess))
			}
			for i := range ovpn.Routing {
				ovpnrouting.WithLabelValues(strconv.Itoa(i+1), ovpn.Routing[i].Client, ovpn.Routing[i].LocalIP, ovpn.Routing[i].RealIP)
			}

			time.Sleep(time.Duration(5 * time.Second))
		}
	}()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>OpenVPN exporter exporter</title></head><body><h1>OpenVPN server stats exporter</h1><p><a href='` + *MetricsPath + `'>Metrics</a></p></body></html>`))
	})
	http.Handle(*MetricsPath, promhttp.Handler())
	log.Info("Listening on: ", *ListenAddr)
	log.Fatal(http.ListenAndServe(*ListenAddr, nil))

}
