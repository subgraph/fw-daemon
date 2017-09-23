const Lang = imports.lang;
const Gio = imports.gi.Gio;

const Extension = imports.misc.extensionUtils.getCurrentExtension();
const Dialog = Extension.imports.dialog;
const Menu = Extension.imports.menu;
//const ConnectionMonitor = Extension.imports.cmonitor;


function init() {
    return new FirewallSupport();
}

const FirewallSupport = new Lang.Class({
    Name: 'FirewallSupport',

    _init: function() {
        this.menu = new Menu.FirewallMenu();
        //this.cmon = new ConnectionMonitor.ConnectionMonitor();
        this.handler = null;
    },

    _destroyHandler: function() {
        if(this.handler) {
            this.handler.destroy();
            this.handler = null;
        }
    },
    enable: function() {
        this._destroyHandler();
        this.handler = new FirewallPromptHandler();
        //this.cmon.install();
        this.menu.install();
    },
    disable: function() {
        this.menu.destroy();
        //this.cmon.remove();
        this._destroyHandler();
    }
});


// $ busctl --user call com.subgraph.FirewallPrompt /com/subgraph/FirewallPrompt com.subgraph.FirewallPrompt TestPrompt
const FirewallPromptInterface = '<node> \
<interface name="com.subgraph.FirewallPrompt"> \
    <method name="RequestPrompt"> \
        <arg type="s" direction="in" name="application" /> \
        <arg type="s" direction="in" name="icon" /> \
        <arg type="s" direction="in" name="path" /> \
        <arg type="s" direction="in" name="address" /> \
        <arg type="i" direction="in" name="port" /> \
        <arg type="s" direction="in" name="ip" /> \
        <arg type="s" direction="in" name="origin" /> \
        <arg type="s" direction="in" name="proto" /> \
        <arg type="i" direction="in" name="uid" /> \
        <arg type="i" direction="in" name="gid" /> \
        <arg type="s" direction="in" name="user" /> \
        <arg type="s" direction="in" name="group" /> \
        <arg type="i" direction="in" name="pid" /> \
        <arg type="s" direction="in" name="sandbox" /> \
        <arg type="b" direction="in" name="tlsguard" /> \
        <arg type="s" direction="in" name="optstring" /> \
        <arg type="b" direction="in" name="expanded" /> \
        <arg type="b" direction="in" name="expert" /> \
        <arg type="i" direction="in" name="action" /> \
        <arg type="i" direction="out" name="scope" /> \
        <arg type="s" direction="out" name="rule" /> \
    </method> \
    <method name="ClosePrompt"/> \
    <method name="TestPrompt"/> \
</interface> \
</node>';

const FirewallPromptHandler = new Lang.Class({
    Name: 'FirewallPromptHandler',

    _init: function() {
        this._dbusImpl = Gio.DBusExportedObject.wrapJSObject(FirewallPromptInterface, this);
        this._dbusImpl.export(Gio.DBus.system, '/com/subgraph/FirewallPrompt');
        Gio.bus_own_name_on_connection(Gio.DBus.system, 'com.subgraph.FirewallPrompt', Gio.BusNameOwnerFlags.REPLACE, null, null);
        this._dialogs = new Array();
    },

    destroy: function() {
        this._closeDialogs();
        this._dbusImpl.unexport();
    },

    _closeDialogs: function() {
        if (this._dialogs.length > 0) {
            dialog = this._dialogs.shift();
            dialog.close();
        }
    },

    RequestPromptAsync: function(params, invocation) {
        let [app, icon, path, address, port, ip, origin, proto, uid, gid, user, group, pid, sandbox, tlsguard, optstring, expanded, expert, action] = params;
        let cbfn = function(self) {
            return function() { return self.onCloseDialog(); }
        }(this)

        let l = this._dialogs.push(new Dialog.PromptDialog(invocation, (pid >= 0), (sandbox != ""), tlsguard, cbfn));
        let dialog = this._dialogs[l-1]
        dialog.update(app, icon, path, address, port, ip, origin, uid, gid, user, group, pid, proto, tlsguard, optstring, sandbox, expanded, expert, action);
        if (this._dialogs.length == 1) {
            dialog.open();
        }
    },

    onCloseDialog: function() {
        this._dialogs.shift();
        if (this._dialogs.length > 0) {
            this._dialogs[0].open();
        }
    },

    CloseAsync: function(params, invocation) {
        this._closeDialogs();
    },

    TestPrompt: function(params, invocation) {
        this.RequestPromptAsync(["Firefox", "firefox", "/usr/bin/firefox-esr", "242.12.111.18", "443", "linux", "2342", "TCP", true, true], nil);
    }
});

