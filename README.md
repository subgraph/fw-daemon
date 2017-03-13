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

View more documentation in the [Subgraph OS Handbook](https://subgraph.com/sgos-handbook/sgos_handbook.shtml#monitoring-outgoing-connections-with-subgraph-firewall).


## Building


```
	# To build the Debian package:
	git clone -b debian https://github.com/subgraph/fw-daemon.git
	cd fw-daemon
	# To build from stable
	gbp buildpackage -us -uc
	# To buiild the latest tag
	gbp buildpackage -us -uc --git-upstream-tree=master
	# Install the package
	dpkg -i /tmp/build-area/fw-daemon{,-gnome}-*.deb
	# Refresh your gnome-shell session 'alt-r' type 'r' hit enter.
```
