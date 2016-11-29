# Subgraph Firewall

A desktop application firewall for Subgraph OS.

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
