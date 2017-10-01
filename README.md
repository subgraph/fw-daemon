# Subgraph Firewall

A desktop application firewall for Subgraph OS.

**Subgraph Firewall** is an application firewall that is included in Subgraph OS.
While most firewalls are designed to handle incoming network communications, an
application firewall can handle outgoing network communications. **Subgraph Firewall**
can apply policies to outgoing connections on a per-application basis.

_Application firewalls_ are useful for monitoring unexpected connections from applications.
For example, some applications may _phone home_ to the vendor's website.
Often this activity is legitimate (non-malicious) but it still may violate the user's
privacy or expectations of how the software operates.
**Subgraph Firewall** gives users the choice to allow or deny these connections.

Malicious code may also _phone home_ to a website or server that is operated by the
hacker or malicious code author. Subgraph Firewall can also alert the user of these connections so that they can be denied.

_Application firewalls_ cannot prevent all malicious code from connecting to the Internet.
Sophisticated malicious code can subvert the _allowed_ connections to bypass the firewall.
However, the firewall may alert the user of connection attempts by less sophisticated malicious code.

The configuration settings for Subgraph Firewall are stored in /etc/sgfw.

From /etc/sgfw/sgfw.conf:

Log level specifies the level of verbosity of logging:

		LogLevel = "NOTICE"
    
Log redaction this tells SGFW to write destination hostnames to system logs, or not:

		LogRedact = true / false

PromptExpanded controls the level of detail in the prompt:

		PromptExpanded = true / false
    
PromptExpert enables or disables "export mode":

		PromptExpert = true / false
    
Specifies the default rule action:

		DefaultAction = "SESSION"

Read more in the [Subgraph OS Handbook](https://subgraph.com/sgos-handbook/sgos_handbook.shtml#monitoring-outgoing-connections-with-subgraph-firewall).


## Building


```
# First install the build dependencies
apt install debhelper dh-golang dh-systemd golang-go libcairo2-dev libglib2.0-dev libgtk-3-dev libnetfilter-queue-dev
# To build the Debian package:
git clone -b debian https://github.com/subgraph/fw-daemon.git
cd fw-daemon
## To build from stable
gbp buildpackage -us -uc
## To build from head
gbp buildpackage -us -uc --git-upstream-tree=master
## Install the package
dpkg -i /tmp/build-area/fw-daemon{,-gnome}-*.deb
## Refresh your gnome-shell session 'alt-r' type 'r' hit enter.
```

You will be left to install the matching iptables rules. While this may vary depending on your environment, pre-existing ruleset
and preferred mechanism; something like the following needs to be added:

```
iptables -t mangle -A OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass
iptables -A INPUT -p udp -m udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -A OUTPUT -p tcp -m mark --mark 0x1 -j LOG
iptables -A OUTPUT -p tcp -m mark --mark 0x1 -j REJECT --reject-with icmp-port-unreachable

```
