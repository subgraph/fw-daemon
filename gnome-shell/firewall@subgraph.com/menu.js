const Lang = imports.lang;

const Main = imports.ui.main;
const PopupMenu = imports.ui.popupMenu;


const FirewallMenu = new Lang.Class({
    Name: 'FirewallSupport',

    _init: function() {
        this.aggregate = Main.panel.statusArea.aggregateMenu;
    },

    install: function() {
        this.createMenu();
        let idx = this.findMenu(this.aggregate._power.menu);
        if(idx >= 0) {
            this.aggregate.menu.addMenuItem(this.menu, idx);
        }
    },

    destroy: function() {
        if(this.menu) {
            this.menu.destroy();
            this.menu = null;
        }
    },

    findMenu: function(menu) {
        let items = this.aggregate.menu._getMenuItems();
        for(let i = 0; i < items.length; i++) {
            if(items[i] == menu) {
                return i;
            }
        }
        return -1;
    },

    createMenu: function() {
        if(this.menu) {
            this.menu.destroy();
        }
        this.menu = new PopupMenu.PopupMenuSection();
        this.item = new PopupMenu.PopupSubMenuMenuItem("Firewall", true);
        this.item.icon.icon_name = "security-high-symbolic";
        this.toggle = new PopupMenu.PopupSwitchMenuItem("Firewall Enabled", false);
        this.toggle.connect('toggled', Lang.bind(this, this.onToggle));
        this.item.menu.addMenuItem(this.toggle);

        this.item.menu.addAction("Connection Monitor", Lang.bind(this, this.onMonitor));
        this.item.menu.addAction("Firewall Settings", Lang.bind(this, this.onSettings));
        this.menu.addMenuItem(this.item);
    },

    onToggle: function() {
        if(this.toggle.state) {
            log("Toggle ON");
        } else {
            log("Toggle OFF");
        }
    },

    onSettings: function() {
        log("Firewall Settings clicked");
    },

    onMonitor: function() {
        log("Connection monitor clicked");
    },
});