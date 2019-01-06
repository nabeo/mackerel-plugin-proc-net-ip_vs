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

// IpvsVirtualServer struct
type IpvsVirtualServer struct {
  IPAddress string
  Port string
  Protocol string
  Schedule string
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

// define graph
var graphdef = map[string]mp.Graphs{
  "proc.net.ip_vs.*.active_conns": {
    Label: "IPVS Real Server (ActiveConn)",
    Unit: mp.UnitInteger,
    Metrics: []mp.Metrics {
      {Name: "*", Label: "Real Server", Diff: false},
    },
  },
  "proc.net.ip_vs.*.inactive_conns": {
    Label: "IPVS Real Server (InActConn)",
    Unit: mp.UnitInteger,
    Metrics: []mp.Metrics {
      {Name: "*", Label: "Real Server", Diff: false},
    },
  },
  "proc.net.ip_vs.*.weight": {
    Label: "IPVS Real Server (Weight)",
    Unit: mp.UnitInteger,
    Metrics: []mp.Metrics {
      {Name: "*", Label: "Real Server", Diff: false},
    },
  },
}

// GraphDefinition : interface for go-mackerel-plugin
func (r IpvsPlugin) GraphDefinition() map[string]mp.Graphs {
  return graphdef
}

// FetchMetrics : interface for go-mackerel-plugin
func (r IpvsPlugin) FetchMetrics() (map[string]float64, error) {
  file, err := os.Open(r.Target)
  if err != nil {
    return nil, err
  }

  return Parse(file)
}

// Parse : /proc/net/ip_vs parser
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
    if fields[0] == "Port" && fields[1] == "LocalAddress:Port" {
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

// GraphKey ...
func GraphKey(base []string) (string, error) {
  graphNamePrefixTemplate := "proc.net.ip_vs.*"
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
  return strings.Replace(graphNamePrefixTemplate, "*", strings.Join(m[:],"_"), 1), nil
  
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
