Before running fw-daemon, make sure to export: GODEBUG=cgocheck=0

Also, here's a default fw-daemon-socks.json config file:

root@subgraph:/# cat /etc/fw-daemon-socks.json 
{
	"SocksListener": "tcp|127.0.0.1:9998",
	"TorSocks": "tcp|127.0.0.1:9050"
}


Remember that fw-settings will need to be compiled separately with go install .../fw-daemon/fw-settings
And the gnome-shell interface must be refreshed with ALT+F2, r
*** All changes require on the interoperation between the latest versions of fw-daemon, fw-settings, and the gnome-shell Javascript frontend.



These rules will need to be sent to ensure that all passed through/sandboxed(clearnet) traffic will be picked up by the firewall:
iptables -t mangle -I PREROUTING 1 -m conntrack --ctstate NEW --proto tcp -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I FORWARD 1 -m mark --mark 0x1 -j REJECT --reject-with icmp-host-prohibited

The following rules are likewise necessary for fw-daemon to catch udp and icmp data:
iptables -t mangle -I PREROUTING 1 --proto udp -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t mangle -I PREROUTING 1 --proto icmp -j NFQUEUE --queue-num 0 --queue-bypass



Here are some examples of the newly formatted rules in /var/lib/sgfw/sgfw_rules:

#[[unknown]] is used to match an unknown process; this is necessary because even though we can sometimes figure out who's sending an ICMP packet, it's functionally impossible for us to tell who the recipient of an ICMP packet is.
[[unknown]]
ALLOW|icmp:4.2.2.4:0|SYSTEM||

#Note the use of wildcards. These rules are of course redundant, but get the same basic job done.
[/usr/sbin/ntpd]
ALLOW|udp:*.ntp.org:123|SYSTEM||
ALLOW|udp:*:123|SYSTEM||
