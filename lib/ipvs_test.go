package mpipvs

import(
  "testing"
  "strings"

  "github.com/stretchr/testify/assert"
)

func TestGenerateGraphDefinition(t *testing.T) {
  vss := IpvsVirtualServers{
    VirtualServers: []IpvsVirtualServer{
      {
        IPAddress: "192.168.0.1",
        Port: "80",
        Protocol: "TCP",
        Schedule: "wrr",
        RealServers: []IpvsRealServer{
          { IPAddress: "192.168.1.1", Port: "80", Forward: "Tunnel"},
          { IPAddress: "192.168.1.2", Port: "80", Forward: "Tunnel"},
        },
      },
      {
        IPAddress: "192.168.0.1",
        Port: "443",
        Protocol: "TCP",
        Schedule: "wrr",
        RealServers: []IpvsRealServer{
          { IPAddress: "192.168.1.1", Port: "443", Forward: "Tunnel"},
          { IPAddress: "192.168.1.2", Port: "443", Forward: "Tunnel"},
        },
      },
      {
        IPAddress: "192.168.0.53",
        Port: "53",
        Protocol: "TCP",
        Schedule: "wrr",
        RealServers: []IpvsRealServer{
          { IPAddress: "192.168.1.53", Port: "53", Forward: "Route"},
          { IPAddress: "192.168.2.53", Port: "53", Forward: "Route"},
        },
      },
      {
        IPAddress: "192.168.0.53",
        Port: "53",
        Protocol: "UDP",
        Schedule: "wrr",
        RealServers: []IpvsRealServer{
          { IPAddress: "192.168.1.53", Port: "53", Forward: "Route"},
          { IPAddress: "192.168.2.53", Port: "53", Forward: "Route"},
        },
      },
    },
  }

  graphdef := GenerateGraphDefinition(vss)

  assert.Len(t, graphdef, 12)

  a := graphdef["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.active_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.inactive_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.weight"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.active_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.inactive_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.weight"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.active_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.inactive_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.weight"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.active_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.inactive_conns"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)

  a = graphdef["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.weight"]
  assert.EqualValues(t, "integer", a.Unit)
  assert.Len(t, a.Metrics, 1)
  assert.EqualValues(t,   "#", a.Metrics[0].Name)
  assert.EqualValues(t, false, a.Metrics[0].Diff)
  assert.EqualValues(t, false, a.Metrics[0].Stacked)
  assert.EqualValues(t,     0, a.Metrics[0].Scale)
}

func TestParse(t *testing.T) {
  s1 := `IP Virtual Server version 1.2.1 (size=1048576)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port Forward Weight ActiveConn InActConn
TCP C0A80001:0050 wrr
  -> C0A80101:0050      Tunnel  10     3          242
  -> C0A80102:0050      Tunnel  100    35         120
TCP C0A80001:01BB wrr
  -> C0A80101:01BB      Tunnel  10     100        80
  -> C0A80102:01BB      Tunnel  100    1200       120
TCP C0A80035:0035 wrr
  -> C0A80135:0035      Route   100    5          67
  -> C0A80235:0035      Route	  100    7          95
UDP C0A80035:0035 wrr
  -> C0A80135:0035      Route   100    12         25
  -> C0A80235:0035      Route	  100    15         30
`
  stubData1 := strings.NewReader(s1)

  a, err := Parse(stubData1)
  assert.Nil(t, err)
  assert.Len(t, a, 24)
  // TCP C0A80001:0050 wrr
  // -> C0A80101:0050      Tunnel  10     3          242
  assert.EqualValues(t, 10, a["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.weight.192_168_1_1_80"])
  assert.EqualValues(t, 3, a["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.active_conns.192_168_1_1_80"])
  assert.EqualValues(t, 242, a["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.inactive_conns.192_168_1_1_80"])
  // -> C0A80102:0050      Tunnel  100    35         120
  assert.EqualValues(t, 100, a["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.weight.192_168_1_2_80"])
  assert.EqualValues(t, 35, a["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.active_conns.192_168_1_2_80"])
  assert.EqualValues(t, 120, a["proc.net.ip_vs.192_168_0_1_80_TCP_wrr.inactive_conns.192_168_1_2_80"])
  // TCP C0A80001:01BB wrr
  // -> C0A80101:01BB      Tunnel  10     100        80
  assert.EqualValues(t, 10, a["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.weight.192_168_1_1_443"])
  assert.EqualValues(t, 100, a["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.active_conns.192_168_1_1_443"])
  assert.EqualValues(t, 80, a["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.inactive_conns.192_168_1_1_443"])
  // -> C0A80102:01BB      Tunnel  100    1200       120
  assert.EqualValues(t, 100, a["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.weight.192_168_1_2_443"])
  assert.EqualValues(t, 1200, a["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.active_conns.192_168_1_2_443"])
  assert.EqualValues(t, 120, a["proc.net.ip_vs.192_168_0_1_443_TCP_wrr.inactive_conns.192_168_1_2_443"])
  // TCP C0A80035:0035 wrr
  // -> C0A80135:0035      Route   100    5          67
  assert.EqualValues(t, 100, a["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.weight.192_168_1_53_53"])
  assert.EqualValues(t, 5, a["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.active_conns.192_168_1_53_53"])
  assert.EqualValues(t, 67, a["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.inactive_conns.192_168_1_53_53"])
  // -> C0A80235:0035      Route	 100    7          95
  assert.EqualValues(t, 100, a["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.weight.192_168_2_53_53"])
  assert.EqualValues(t, 7, a["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.active_conns.192_168_2_53_53"])
  assert.EqualValues(t, 95, a["proc.net.ip_vs.192_168_0_53_53_TCP_wrr.inactive_conns.192_168_2_53_53"])
  // UDP C0A80035:0035 wrr
  // -> C0A80135:0035      Route   100    12         25
  assert.EqualValues(t, 100, a["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.weight.192_168_1_53_53"])
  assert.EqualValues(t, 12, a["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.active_conns.192_168_1_53_53"])
  assert.EqualValues(t, 25, a["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.inactive_conns.192_168_1_53_53"])
  // -> C0A80235:0035      Route	 100    15         30
  assert.EqualValues(t, 100, a["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.weight.192_168_2_53_53"])
  assert.EqualValues(t, 15, a["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.active_conns.192_168_2_53_53"])
  assert.EqualValues(t, 30, a["proc.net.ip_vs.192_168_0_53_53_UDP_wrr.inactive_conns.192_168_2_53_53"])
}

func TestHex2IpvsServer(t *testing.T) {
  // C0A80001:0050 -> 192.168.0.1:80
  a, err := Hex2IpvsServer("C0A80001:0050")
  assert.Nil(t, err)
  assert.EqualValues(t, "192.168.0.1", a.IPAddress)
  assert.EqualValues(t, "80", a.Port)
  // C0A80001:01BB -> 192.168.0.1:443
  b, err := Hex2IpvsServer("C0A80001:01BB")
  assert.Nil(t, err)
  assert.EqualValues(t, "192.168.0.1", b.IPAddress)
  assert.EqualValues(t, "443", b.Port)
}

func TestGraphKey(t *testing.T) {
  // TCP C0A80001:0050 wrr -> proc.net.ip_vs.192_168_0_1_80_TCP_wrr
  a, err := GraphKey(strings.Fields("TCP C0A80001:0050 wrr"))
  assert.Nil(t, err)
  assert.EqualValues(t, "proc.net.ip_vs.192_168_0_1_80_TCP_wrr", a)
}

func TestParseStructer(t *testing.T) {
  s1 := `IP Virtual Server version 1.2.1 (size=1048576)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port Forward Weight ActiveConn InActConn
TCP C0A80001:0050 wrr
  -> C0A80101:0050      Tunnel  10     3          242
  -> C0A80102:0050      Tunnel  100    35         120
TCP C0A80001:01BB wrr
  -> C0A80101:01BB      Tunnel  10     100        80
  -> C0A80102:01BB      Tunnel  100    1200       120
TCP C0A80035:0035 wrr
  -> C0A80135:0035      Route   100    5          67
  -> C0A80235:0035      Route	  100    7          95
UDP C0A80035:0035 wrr
  -> C0A80135:0035      Route   100    12         25
  -> C0A80235:0035      Route	  100    15         30
`
  stubData1 := strings.NewReader(s1)

  a, err := ParseStructer(stubData1)
  assert.Nil(t, err)
  assert.EqualValues(t, 4, len(a.VirtualServers))
  // TCP C0A80001:0050 wrr
  //   -> C0A80101:0050      Tunnel  10     3          242
  //   -> C0A80102:0050      Tunnel  100    35         120
  assert.EqualValues(t,         "TCP", a.VirtualServers[0].Protocol)
  assert.EqualValues(t, "192.168.0.1", a.VirtualServers[0].IPAddress)
  assert.EqualValues(t,          "80", a.VirtualServers[0].Port)
  assert.EqualValues(t,         "wrr", a.VirtualServers[0].Schedule)
  assert.EqualValues(t, 2, len(a.VirtualServers[0].RealServers))
  assert.EqualValues(t, "192.168.1.1", a.VirtualServers[0].RealServers[0].IPAddress)
  assert.EqualValues(t,          "80", a.VirtualServers[0].RealServers[0].Port)
  assert.EqualValues(t,      "Tunnel", a.VirtualServers[0].RealServers[0].Forward)
  assert.EqualValues(t, "192.168.1.2", a.VirtualServers[0].RealServers[1].IPAddress)
  assert.EqualValues(t,          "80", a.VirtualServers[0].RealServers[1].Port)
  assert.EqualValues(t,      "Tunnel", a.VirtualServers[0].RealServers[1].Forward)
  // TCP C0A80001:01BB wrr
  //   -> C0A80101:01BB      Tunnel  10     100        80
  //   -> C0A80102:01BB      Tunnel  100    1200       120
  assert.EqualValues(t,         "TCP", a.VirtualServers[1].Protocol)
  assert.EqualValues(t, "192.168.0.1", a.VirtualServers[1].IPAddress)
  assert.EqualValues(t,         "443", a.VirtualServers[1].Port)
  assert.EqualValues(t,         "wrr", a.VirtualServers[1].Schedule)
  assert.EqualValues(t, 2, len(a.VirtualServers[1].RealServers))
  assert.EqualValues(t, "192.168.1.1", a.VirtualServers[1].RealServers[0].IPAddress)
  assert.EqualValues(t,         "443", a.VirtualServers[1].RealServers[0].Port)
  assert.EqualValues(t,      "Tunnel", a.VirtualServers[1].RealServers[0].Forward)
  assert.EqualValues(t, "192.168.1.2", a.VirtualServers[1].RealServers[1].IPAddress)
  assert.EqualValues(t,         "443", a.VirtualServers[1].RealServers[1].Port)
  assert.EqualValues(t,      "Tunnel", a.VirtualServers[1].RealServers[1].Forward)
  // TCP C0A80035:0035 wrr
  //   -> C0A80135:0035      Route   100    5          67
  //   -> C0A80235:0035      Route   100    7          95
  assert.EqualValues(t,          "TCP", a.VirtualServers[2].Protocol)
  assert.EqualValues(t, "192.168.0.53", a.VirtualServers[2].IPAddress)
  assert.EqualValues(t,           "53", a.VirtualServers[2].Port)
  assert.EqualValues(t,          "wrr", a.VirtualServers[2].Schedule)
  assert.EqualValues(t, 2, len(a.VirtualServers[2].RealServers))
  assert.EqualValues(t, "192.168.1.53", a.VirtualServers[2].RealServers[0].IPAddress)
  assert.EqualValues(t,           "53", a.VirtualServers[2].RealServers[0].Port)
  assert.EqualValues(t,        "Route", a.VirtualServers[2].RealServers[0].Forward)
  assert.EqualValues(t, "192.168.2.53", a.VirtualServers[2].RealServers[1].IPAddress)
  assert.EqualValues(t,           "53", a.VirtualServers[2].RealServers[1].Port)
  assert.EqualValues(t,        "Route", a.VirtualServers[2].RealServers[1].Forward)
  // UDP C0A80035:0035 wrr
  //   -> C0A80135:0035      Route   100    12         25
  //   -> C0A80235:0035      Route   100    15         30
  assert.EqualValues(t,          "UDP", a.VirtualServers[3].Protocol)
  assert.EqualValues(t, "192.168.0.53", a.VirtualServers[3].IPAddress)
  assert.EqualValues(t,           "53", a.VirtualServers[3].Port)
  assert.EqualValues(t,          "wrr", a.VirtualServers[3].Schedule)
  assert.EqualValues(t, 2, len(a.VirtualServers[3].RealServers))
  assert.EqualValues(t, "192.168.1.53", a.VirtualServers[3].RealServers[0].IPAddress)
  assert.EqualValues(t,           "53", a.VirtualServers[3].RealServers[0].Port)
  assert.EqualValues(t,        "Route", a.VirtualServers[3].RealServers[0].Forward)
  assert.EqualValues(t, "192.168.2.53", a.VirtualServers[3].RealServers[1].IPAddress)
  assert.EqualValues(t,           "53", a.VirtualServers[3].RealServers[1].Port)
  assert.EqualValues(t,        "Route", a.VirtualServers[3].RealServers[1].Forward)

}
