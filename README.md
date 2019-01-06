mackerel-plugin-proc-net-ip_vs
==============================

mackerel-plugin for /proc/net/ip_vs

## Synopsis

```shell
mackerel-plugin-proc-net-ip_vs [-target=<path to /proc/net/ip_vs>] [-tempfile=<tempfile>]
```

## Example of mackerel-agent.conf

```ascii
[plugin.metrics.ipvs]
command = "mackerel-plugin-proc-net-ip_vs"
```
