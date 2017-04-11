Before running fw-daemon, make sure to export: GODEBUG=cgocheck=0

Also, here's a default fw-daemon-socks.json config file:

root@subgraph:/# cat /etc/fw-daemon-socks.json 
{
	"SocksListener": "tcp|127.0.0.1:9998",
	"TorSocks": "tcp|127.0.0.1:9050"
}

