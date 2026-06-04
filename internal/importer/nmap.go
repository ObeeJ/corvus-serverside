// Package importer ingests external scan formats into the Corvus store. The
// nmap XML importer is the "bridge" that lets existing nmap users pull their
// scans into Corvus for history, anomaly detection, and CVE correlation.
package importer

import (
	"encoding/xml"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

// ParsedPort is one host:port observation ready to persist via store.WriteState.
type ParsedPort struct {
	IP    net.IP
	Port  uint16
	Proto string
	Rec   types.StateRecord
}

// nmapRun mirrors the subset of `nmap -oX` output we care about.
type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   uint16 `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name      string `xml:"name,attr"`
					Product   string `xml:"product,attr"`
					Version   string `xml:"version,attr"`
					ExtraInfo string `xml:"extrainfo,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// ParseNmapXML reads nmap XML and returns the observed ports.
func ParseNmapXML(r io.Reader) ([]ParsedPort, error) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, err
	}

	now := time.Now()
	var out []ParsedPort
	for _, h := range run.Hosts {
		ipStr := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				ipStr = a.Addr
				break
			}
		}
		if ipStr == "" && len(h.Addresses) > 0 {
			ipStr = h.Addresses[0].Addr
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, p := range h.Ports.Ports {
			out = append(out, ParsedPort{
				IP:    ip,
				Port:  p.PortID,
				Proto: strings.ToLower(p.Protocol),
				Rec: types.StateRecord{
					Timestamp:   now,
					Open:        p.State.State == "open",
					ServiceName: p.Service.Name,
					Version:     strings.TrimSpace(p.Service.Product + " " + p.Service.Version),
					Banner:      strings.TrimSpace(p.Service.ExtraInfo),
				},
			})
		}
	}
	return out, nil
}

// ParseNmapFile parses an nmap XML file from disk.
func ParseNmapFile(path string) ([]ParsedPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	return ParseNmapXML(f)
}
