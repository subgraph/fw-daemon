const Lang = imports.lang;
const Gio = imports.gi.Gio;

const Extension = imports.misc.extensionUtils.getCurrentExtension();
const Dialog = Extension.imports.dialog;
const Menu = Extension.imports.menu;

function init() {
    return new FirewallSupport();
}

const FirewallSupport = new Lang.Class({
    Name: 'FirewallSupport',

    _init: function() {
        this.menu = new Menu.FirewallMenu();
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
        this.menu.install();
    },
    disable: function() {
        this.menu.destroy();
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
        <arg type="s" direction="in" name="user" /> \
        <arg type="i" direction="in" name="pid" /> \
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
        this._dialog = null;
    },

    destroy: function() {
        this._closeDialog();
        this._dbusImpl.unexport();
    },

    _closeDialog: function() {
        if (this._dialog) {
            this._dialog.close();
            this._dialog = null;
        }
    },

    RequestPromptAsync: function(params, invocation) {
        let [app, icon, path, address, port, ip, user, pid] = params;
        this._closeDialog();
        this._dialog = new Dialog.PromptDialog(invocation);
        this._invocation = invocation;
        this._dialog.update(app, icon, path, address, port, ip, user, pid);
        this._dialog.open();

    },

    CloseAsync: function(params, invocation) {
        this._closeDialog();
    },

    TestPrompt: function(params, invocation) {
        this._closeDialog();
        this._dialog = new Dialog.PromptDialog(nil);
        this._dialog.update("Firefox", "firefox", "/usr/bin/firefox", "242.12.111.18", "443", "linux", "2342");
        this._dialog.open();
    }
});

