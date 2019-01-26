package mpipvs

import(
  "flag"
  "os"
  "io"
  "bufio"
  "strings"
  "encoding/hex"
  "net"
  "errors"
  "strconv"
  "fmt"

  mp "github.com/mackerelio/go-mackerel-plugin"
)

// IpvsPlugin struct
type IpvsPlugin struct {
  Prefix string
  Target string
  Tempfile string
}

// IpvsVirtualServers struct
type IpvsVirtualServers struct {
  VirtualServers []IpvsVirtualServer
}

// IpvsVirtualServer struct
type IpvsVirtualServer struct {
  IPAddress string
  Port string
  Protocol string
  Schedule string
  RealServers []IpvsRealServer
}

// IpvsRealServer stuct
type IpvsRealServer struct {
  IPAddress string
  Port string
  Forward string
}

// IpvsRealServerStat struct
type IpvsRealServerStat struct {
  IPAddress string
  Port string
  Forward string
  ActConns float64
  InActConns float64
  Weight float64
}

// IpvsServer struct 
type IpvsServer struct {
  IPAddress string
  Port string
}

// GraphNamePrefixTemplate ...
var GraphNamePrefixTemplate = "proc.net.ip_vs.*"

// GraphDefinition : interface for go-mackerel-plugin
// var graphdef = map[string]mp.Graphs{
//   "proc.net.ip_vs.192_168_0_1_80_TCP_wrr.active_conns": {
//     Unit: mp.UnitInteger,
//     Metrics: []mp.Metrics {
//       {Name: "*", Diff: false, Stacked: false},
//     },
//   },
//   "proc.net.ip_vs.192_168_0_1_80_TCP_wrr.inactive_conns": {
//     Unit: mp.UnitInteger,
//     Metrics: []mp.Metrics {
//       {Name: "*", Diff: false, Stacked: false},
//     },
//   },
//   "proc.net.ip_vs.192_168_0_1_80_TCP_wrr.weight": {
//     Unit: mp.UnitInteger,
//     Metrics: []mp.Metrics {
//       {Name: "*", Diff: false, Stacked: false},
//     },
//   },
// }
func (r IpvsPlugin) GraphDefinition() map[string]mp.Graphs {
  file, _ := os.Open(r.Target)
  defer file.Close()
  vss, _ := ParseStructer(file)
  return GenerateGraphDefinition(vss)
}

// ParseStructer : Parse /proc/net/ip_vs to IpvsVirtualServers
// TCP C0A80001:0050 wrr
//   -> C0A80101:0050      Tunnel  10     3          242
//   -> C0A80102:0050      Tunnel  100    35         120
// =>
// vss := IpvsVirtualServers{
//   VirtualServers: []IpvsVirtualServer{
//     {
//       IPAddress: "192.168.0.1",
//       Port: "80",
//       Protocol: "TCP",
//       Schedule: "wrr",
//       RealServers: []IpvsRealServer{
//         { IPAddress: "192.168.1.1", Port: "80", Forward: "Tunnel"},
//         { IPAddress: "192.168.1.2", Port: "80", Forward: "Tunnel"},
//       },
//     },
//   }
func ParseStructer(stat io.Reader) (IpvsVirtualServers, error) {
  var vss IpvsVirtualServers
  var vs IpvsVirtualServer
  scanner := bufio.NewScanner(stat)
  for scanner.Scan() {
    fields := strings.Fields(scanner.Text())
    if fields[0] == "IP" && fields[1] == "Virtual" && fields[2] == "Server" {
      // ignore `IP Virtual Server version ...`
      continue
    }
    if fields[0] == "Prot" && fields[1] == "LocalAddress:Port" {
      // ignore `Prot LocalAddress:Port Scheduler Flags`
      continue
    }
    switch {
    case fields[0] == "TCP" || fields[0] == "UDP" || fields[0] == "SCTP" || fields[0] == "AM" || fields[0] == "ESP":
      // Virtual Server status format
      // <Protocol> <Virtual IP in hex>:<Port number in Hex> <schedule>
      if len(fields) != 3 {
        return vss, errors.New("Virtual Server infomation must have 3 fields")
      }
      t, err := Hex2IpvsServer(fields[1])
      if err != nil {
        return vss, err
      }
      vs.IPAddress = t.IPAddress
      vs.Port = t.Port
      vs.Protocol = fields[0]
      vs.Schedule = fields[2]
      vss.VirtualServers = append(vss.VirtualServers, vs)

    case fields[0] == "->":
      if fields[1] == "RemoteAddress:Port" {
        continue
      }
      if len(fields) != 6 {
        // Skip header line (`-> RemoteAddress:Port Forward Weight ActiveConn InActConn`)
        // Real Server infomation must have 6 fields
        return vss, errors.New("Real Server infomation must have 6 fields")
      }
      var rs IpvsRealServer
      t, err := Hex2IpvsServer(fields[1])
      if err != nil {
        return vss, err
      }
      rs.IPAddress = t.IPAddress
      rs.Port = t.Port
      rs.Forward = fields[2]
      i := len(vss.VirtualServers) - 1
      vss.VirtualServers[i].RealServers = append(vss.VirtualServers[i].RealServers, rs)
    }
  }
  return vss, nil
}

// GenerateGraphDefinition IpvsVirtualServers to map[string]mp.Graphs
func GenerateGraphDefinition(vss IpvsVirtualServers) map[string]mp.Graphs {
  var graphdef = make(map[string]mp.Graphs)
  var graphkeyprefix string
  for _, vs := range vss.VirtualServers {
    var m = [...]string{
      strings.Replace(vs.IPAddress,".","_",-1),
      vs.Port,
      vs.Protocol,
      vs.Schedule,
    }
    graphkeyprefix = strings.Replace(GraphNamePrefixTemplate,"*",strings.Join(m[:],"_"), 1)
    graphdef[graphkeyprefix + ".active_conns"] = mp.Graphs{
      Unit: mp.UnitInteger,
      Label: vs.Protocol + " " + vs.IPAddress + ":" + vs.Port + " " + vs.Schedule + "(active conns)",
      Metrics: []mp.Metrics{
        {Name: "#", Diff: false, Stacked: false},
      },
    }
    graphdef[graphkeyprefix + ".inactive_conns"] = mp.Graphs{
      Unit: mp.UnitInteger,
      Label: vs.Protocol + " " + vs.IPAddress + ":" + vs.Port + " " + vs.Schedule + "(inactive conns)",
      Metrics: []mp.Metrics{
        {Name: "#", Diff: false, Stacked: false},
      },
    }
    graphdef[graphkeyprefix + ".weight"] = mp.Graphs{
      Unit: mp.UnitInteger,
      Label: vs.Protocol + " " + vs.IPAddress + ":" + vs.Port + " " + vs.Schedule + "(weight)",
      Metrics: []mp.Metrics{
        {Name: "#", Diff: false, Stacked: false},
      },
    }
  }
  return graphdef
}

// FetchMetrics : interface for go-mackerel-plugin
func (r IpvsPlugin) FetchMetrics() (map[string]float64, error) {
  file, err := os.Open(r.Target)
  if err != nil {
    return nil, err
  }
  defer file.Close()

  return Parse(file)
}

// Parse : /proc/net/ip_vs parser for FetchMetrics
// TCP C0A80001:0050 wrr
//   -> C0A80101:0050      Tunnel  10     3          242
// =>
// data = {
//   { proc.net.ip_vs.192_168_0_1_80_TCP_wrr.weight.192_168_1_1_80: 10 },
//   { proc.net.ip_vs.192_168_0_1_80_TCP_wrr.active_conns.192_168_1_1_80: 3 },
//   { proc.net.ip_vs.192_168_0_1_80_TCP_wrr.inactive_conns.192_168_1_1_80: 242 },
// }
func Parse(stat io.Reader) (map[string]float64, error) {
  data := make(map[string]float64)
  scanner := bufio.NewScanner(stat)
  var graphNamePrefix string
  for scanner.Scan() {
    fields := strings.Fields(scanner.Text())
    if fields[0] == "IP" && fields[1] == "Virtual" && fields[2] == "Server" {
      // ignore `IP Virtual Server version ...`
      continue
    }
    if fields[0] == "Prot" && fields[1] == "LocalAddress:Port" {
      // ignore `Prot LocalAddress:Port Scheduler Flags`
      continue
    }
    switch {
    case fields[0] == "TCP" || fields[0] == "UDP" || fields[0] == "SCTP" || fields[0] == "AM" || fields[0] == "ESP":
      // Virtual Server status format
      // <Protocol> <Virtual IP in hex>:<Port number in Hex> <schedule>
      if len(fields) != 3 {
        return nil, errors.New("Virtual Server infomation must have 3 fields")
      }
      graphNamePrefix, _ = GraphKey(fields)

    case fields[0] == "->":
      // Real Server status format
      // -> <Real IP in hex>:<Port number in Hex> <Forward> <weight> <active conns> <inactive conn>
      if fields[1] == "RemoteAddress:Port" {
        // skip header line
        continue
      }
      if len(fields) != 6 {
        return nil, errors.New("Real Server infomation must have 6 fields")
      }
      var rs IpvsRealServerStat
      RealServerInfo, err := Hex2IpvsServer(fields[1])
      if err != nil {
        return nil, err
      }
      rs.IPAddress = RealServerInfo.IPAddress
      rs.Port = RealServerInfo.Port
      var rsKey = [...]string{
        strings.Replace(rs.IPAddress,".","_",-1),
        rs.Port,
      }
      rs.Forward = fields[2]

      rs.Weight, err = strconv.ParseFloat(fields[3], 64)
      if err != nil {
        return nil, err
      }
      data[graphNamePrefix + "." + "weight" + "." + strings.Join(rsKey[:], "_")] = rs.Weight

      rs.ActConns, err = strconv.ParseFloat(fields[4], 64)
      if err != nil {
        return nil, err
      }
      data[graphNamePrefix + "." + "active_conns" + "." + strings.Join(rsKey[:], "_")] = rs.ActConns

      rs.InActConns, err = strconv.ParseFloat(fields[5], 64)
      if err != nil {
        return nil, err
      }
      data[graphNamePrefix + "." + "inactive_conns" + "." + strings.Join(rsKey[:], "_")] = rs.InActConns
    }
  }
  return data, nil
}

// Hex2IpvsServer : "<IP Addr in hex>:<Port in hex>" to IpvsServer
// C0A80001:0050
// =>
// data = {
//   IPAddress: "192.168.0.1",
//   Port: "80",
// }
func Hex2IpvsServer(s string) (IpvsServer, error) {
  var data IpvsServer
  a := strings.Split(s, ":")
  IPSlice, err := hex.DecodeString(a[0])
  if err != nil {
    return data, err
  }
  data.IPAddress = net.IPv4(IPSlice[0], IPSlice[1], IPSlice[2], IPSlice[3]).String()
  PortNum, err := strconv.ParseInt(a[1], 16, 64)
  if err != nil {
    return data, err
  }
  data.Port = fmt.Sprint(PortNum)
  return data, nil
}

// GraphKey : convert virtual server string to graphkey
// `TCP C0A80001:0050 wrr` => `proc.net.ip_vs` + `.192_168_0_1_80_TCP_wrr`
func GraphKey(base []string) (string, error) {
  var a IpvsVirtualServer
  a.Protocol = base[0]
  a.Schedule = base[2]
  VirtualServerInfo, err := Hex2IpvsServer(base[1])
  if (err != nil) {
    return "", err
  }
  a.IPAddress = VirtualServerInfo.IPAddress
  a.Port = VirtualServerInfo.Port
  var m = [...]string{
    strings.Replace(a.IPAddress,".","_",-1),
    a.Port,
    a.Protocol,
    a.Schedule,
  }
  return strings.Replace(GraphNamePrefixTemplate, "*", strings.Join(m[:],"_"), 1), nil
}

// Do : Do plugin
func Do() {
  optTarget := flag.String("target", "/proc/net/ip_vs", "path to /proc/net/ip_vs")
  optTempfile := flag.String("tempfile", "", "Temp file name")
  flag.Parse()

  var r IpvsPlugin
  r.Target = *optTarget

  helper := mp.NewMackerelPlugin(r)
  helper.Tempfile = *optTempfile

  helper.Run()
}
