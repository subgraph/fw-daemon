To get this to work, first edit /usr/share/gnome-shell/modes/subgraph.json
Remove the entry for "firewall@subgraph.com", hit CTRL+F2 and then issue the reload "r" command.
Reset these changes to revert back to the old gnome-shell prompt.




Changes for getting this working in ubuntu:
(this is the crux of, but not all of the steps necessary to get this running)

apt-get install libnetfilter-queue-dev
#apt-get install all dependencies: gtk3/cairo/pango/glib etc.


mkdir /etc/sgfw
cat >> /etc/sgfw/sgfw.conf << EOF
log_level="NOTICE"
log_redact=false
prompt_expanded=true
prompt_expert=true
default_action="SESSION"
EOF


cp ./src/github.com/subgraph/fw-daemon/sources/etc/dbus-1/system.d/com.subgraph.Firewall.conf /etc/dbus-1/system.d/com.subgraph.Firewall.conf
iptables -t mangle -I PREROUTING 1 -m conntrack --ctstate NEW --proto tcp -j NFQUEUE --queue-num 0 --queue-bypass; iptables -I FORWARD 1 -m mark --mark 0x1 -j REJECT --reject-with icmp-host-prohibited

go install github.com/subgraph/fw-daemon
go install github.com/subgraph/fw-daemon/fw-settings
go install github.com/subgraph/fw-daemon/fw-prompt

GODEBUG=cgocheck=0 ./fw-daemon
Then launch ./fw-prompt
