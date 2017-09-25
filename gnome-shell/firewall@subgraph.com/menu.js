const Lang = imports.lang;
const Gio = imports.gi.Gio;

const Main = imports.ui.main;
const PopupMenu = imports.ui.popupMenu;
const Util = imports.misc.util;

const FirewallInterface = '<node> \
<interface name="com.subgraph.Firewall"> \
  <method name="SetEnabled"> \
    <arg name="enabled" direction="in" type="b" /> \
  </method> \
  <method name="IsEnabled"> \
    <arg name="enabled" direction="out" type="b" /> \
  </method> \
</interface>\
</node>';

const FirewallProxy = Gio.DBusProxy.makeProxyWrapper(FirewallInterface);

const FirewallMenu = new Lang.Class({
    Name: 'FirewallSupport',

    _init: function() {
        this.proxy = new FirewallProxy(Gio.DBus.system, "com.subgraph.Firewall",
        "/com/subgraph/Firewall", Lang.bind(this, function(proxy, error) {
            if (error) {
                log(error.message);
                return;
            }
        }));
        this.aggregate = Main.panel.statusArea.aggregateMenu;
    },

    install: function() {
        this.createMenu();
        this.menu.connect('open-state-changed', Lang.bind(this, this.openStateChanged));
        let idx = this.findMenu(this.aggregate._power.menu);
        if (idx >= 0) {
            this.aggregate.menu.addMenuItem(this.menu, idx);
        }
    },

    openStateChanged: function() {
        this.proxy.IsEnabledRemote(Lang.bind(this, function(result, err) {
            if (err) {
                log(err.message);
                return;
            }
            let [enabled] = result;
            this.toggle.setToggleState(enabled);
        }));
    },

    destroy: function() {
        if (this.menu) {
            this.menu.destroy();
            this.menu = null;
        }
    },

    findMenu: function(menu) {
        let items = this.aggregate.menu._getMenuItems();
        for(let i = 0; i < items.length; i++) {
            if (items[i] == menu) {
                return i;
            }
        }
        return -1;
    },

    createMenu: function() {
        if (this.menu) {
            this.menu.destroy();
        }
        this.menu = new PopupMenu.PopupMenuSection();
        this.item = new PopupMenu.PopupSubMenuMenuItem("Firewall", true);
        this.item.icon.icon_name = "security-high-symbolic";
        this.toggle = new PopupMenu.PopupSwitchMenuItem("Firewall Enabled", true);
        this.toggle.connect('toggled', Lang.bind(this, this.onToggle));
        this.item.menu.addMenuItem(this.toggle);

        //this.item.menu.addAction("Connection Monitor", Lang.bind(this, this.onMonitor));
        this.item.menu.addAction("Firewall Settings", Lang.bind(this, this.onSettings));
        this.menu.addMenuItem(this.item);
    },

    onToggle: function() {
        if (this.toggle.state) {
            log("Toggle ON");
        } else {
            log("Toggle OFF");
        }
        this.proxy.SetEnabledRemote(this.toggle.state);
    },

    onSettings: function() {
        Util.spawnCommandLine("/usr/bin/fw-settings")
    },

    onMonitor: function() {
        log("Connection monitor clicked");
    },
});
