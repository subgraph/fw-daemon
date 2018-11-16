const Lang = imports.lang;
const Mainloop = imports.mainloop;

const Main = imports.ui.main;

const Meta = imports.gi.Meta;
const Shell = imports.gi.Shell;
const Gio = imports.gi.Gio;
const GLib = imports.gi.GLib;

const Extension = imports.misc.extensionUtils.getCurrentExtension();
const Convenience = Extension.imports.convenience;

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
        if (this.handler) {
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


const FirewallPromptInterface = '<node> \
<interface name="com.subgraph.FirewallPrompt"> \
    <method name="RequestPromptAsync"> \
        <arg type="s" direction="in" name="guid" /> \
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
        <arg type="s" direction="in" name="timestamp" /> \
        <arg type="s" direction="in" name="optstring" /> \
        <arg type="b" direction="in" name="expanded" /> \
        <arg type="b" direction="in" name="expert" /> \
        <arg type="i" direction="in" name="action" /> \
        <arg type="b" direction="out" name="result" /> \
    </method> \
    <method name="RemovePrompt"> \
        <arg type="s" direction="in" name="guid" /> \
        <arg type="b" direction="out" name="result" /> \
    </method> \
</interface> \
</node>';

const FirewallPromptHandler = new Lang.Class({
    Name: 'FirewallPromptHandler',

    _init: function() {
        this._settings = Convenience.getSettings();
        this._dbusImpl = Gio.DBusExportedObject.wrapJSObject(FirewallPromptInterface, this);
        this._dbusImpl.export(Gio.DBus.system, '/com/subgraph/FirewallPrompt');
        Gio.bus_own_name_on_connection(Gio.DBus.system, 'com.subgraph.FirewallPrompt', Gio.BusNameOwnerFlags.REPLACE, null, null);
        this._dialogs = new Object();
        this._dialog = null;
        this._guids = new Array();
        this._current_guid = null;
        this._timeoutId = null;
        this._initKeybindings();
        this.RequestPendingPrompts();
    },

    destroy: function() {
        log("SGFW: Exited");
        this._closeDialogs();
        this._dbusImpl.unexport();
        this._destroyKeybindings();
        if (this._timeoutId !== null) {
            Mainloop.source_remove(this._timeoutId);
            this._timeoutId = null;
        }
    },

    _initKeybindings: function() {
        this._keyBindings = new Array(
            "prompt-scope-previous"
            , "prompt-scope-next"
            , "prompt-rule-next"
            , "prompt-rule-previous"
            , "prompt-rule-allow"
            , "prompt-rule-deny"
            , "prompt-toggle-details"
            , "prompt-toggle-tlsguard"
        );
        for (var i = 0 , ii = this._keyBindings.length; i < ii; i++) {
            Main.wm.addKeybinding(this._keyBindings[i],
                          this._settings,
                          Meta.KeyBindingFlags.NONE,
                          Shell.ActionMode.ALL,
                          Lang.bind(this, this._handleKeybinding, this._keyBindings[i]));
        }
    },

    _handleKeybinding: function(a, b, c, d, binding) {
        if (this._dialog === null) {
            return false;
        }

       // let fname = binding.replace(/-([a-z])/g, function (g) { return g[1].toUpperCase(); });
        let fname = "_on"+ fname[0].toUpperCase() + fname.substr(1);
        if (!( fname in this._dialog )) {
            log("SGFW: Invalid key binding (1)... " + fname);
            return true;
        }
        let fn = this._dialog[fname];
        if (typeof fn !== "function") {
            log("SGFW: Invalid key binding (2)... " + fname + " " + (typeof fn));
            return true;
        }

        Lang.bind(this._dialog, fn)();
        return true;
    },

    _destroyKeybindings: function() {
        for (var i = 0 , ii = this._keyBindings.length; i < ii; i++) {
            Main.wm.removeKeybinding(this._keyBindings[i]);
        }
    },

    _closeDialogs: function() {
        log("SGFW: Closing all dialogs");
        if (this._dialog !== null) {
            this._dialog.close();
            this._dialog = null;
        }
        this._dialogs = new Object();
        this._guids = new Array();
        this._current_guid = null;
    },

    RequestPendingPrompts: function() {
        try {
            let params = GLib.Variant.new("(s)", ["*"]);
            let result = Gio.DBus.system.call_sync("com.subgraph.Firewall",
                                                    "/com/subgraph/Firewall",
                                                    "com.subgraph.Firewall",
                                                    "GetPendingRequests", params, null,
                                                    Gio.DBusCallFlags.NONE, 500, null);
            log("SGFW: Get Pending Requests: " + result.deep_unpack());
        } catch (err if err.matches(Gio.DBusError, Gio.DBusError.SERVICE_UNKNOWN)) {
            return;
        } catch (err) {
            log("SGFW: Fatal Error Requesting Pending Prompts: "+ err);
        }
    },

    RequestPromptAsyncAsync: function(params) {
        try {
            if (this._dialog == null) {
                this._dialog = true;
                
                let guid = params.shift();
                this._dialogs[guid] = params;
                this._guids.push(guid);
                
                this._createDialog(guid);
            } else {
                let guid = params.shift();
                this._dialogs[guid] = params;
                this._guids.push(guid);
                
                this._updateDialogRemainingPrompts();
            }
            log("SGFW: Async Prompt Requested " + params);
        } catch (err) {
            log("SGFW: Error on async prompt request: " + err);
        } 
    },

    RemovePromptAsync: function(params, invocation) {
        let [guid] = params;
        log("SGFW: Async Prompt Remove " + guid + " " + (guid in this._dialogs));
        try {
            if (guid == this._current_guid) {
                this._dialog = null;
                this._current_guid = null;
            }
            
            if (guid in this._dialogs) {
                delete this._dialogs[guid];
                for (let ii = (this._guids.length - 1); ii >= 0; ii--) {
                    if (this._guids[ii] === guid) {
                        this._guids.splice(ii,1);
                        break;
                    }
                }

                invocation.return_value(GLib.Variant.new('(b)', [true]));
            } else {
                invocation.return_value(GLib.Variant.new('(b)', [false]));
            }
            if (this._dialog !== null) {
                this._updateDialogRemainingPrompts();
            }
        } catch (err) {
            log("SGFW: Error on async prompt remove: " + err);
        }

        try {
            if (this._timeoutId == null) {
                log("SGFW: Waiting to check for next dialog...");
                this._timeoutId = Mainloop.timeout_add_seconds(1, Lang.bind(this, this._createNextDialogCallback));
            } else {
                log("SGFW: Already waiting for next dialog...");
            }
        } catch (err) {
            log("SGFW: Error while setting up next event display timeout: " + err);
        }
    },

    AddRuleCallback: function(guid, timestamp, rule, scope) {
        log("SGFW: Adding rule for " + guid + " " + timestamp + ": " + rule + " (" + scope + ")");
        try {
            let params = GLib.Variant.new("(usss)", [scope, rule, "*", guid]);
            let result = Gio.DBus.system.call_sync("com.subgraph.Firewall",
                                                    "/com/subgraph/Firewall",
                                                    "com.subgraph.Firewall",
                                                    "AddRuleAsync", params, null,
                                                    Gio.DBusCallFlags.NONE, 500, null);
            log("SGFW: Add Rule Async: " + result.deep_unpack());
            // XXXX: If false prompt user about failure
        } catch (err) {
            log("SGFW: Fatal Error: " + err);
        }
    },

    _createDialog: function(guid) {
        log("SGFW: Creating new prompt for: " + this._dialogs[guid]);
        try {
            let [app, icon, path, address, port, ip, origin, proto, uid, gid, user, group, pid, sandbox, tlsguard, timestamp, optstring, expanded, expert, action] = this._dialogs[guid];
            this._current_guid = guid;
            this._dialog = new Dialog.PromptDialog(guid, timestamp, (pid >= 0), (sandbox != ""), tlsguard, Lang.bind(this, this.AddRuleCallback));
            this._dialog.update(app, icon, path, address, port, ip, origin, uid, gid, user, group, pid, proto, tlsguard, optstring, sandbox, expanded, expert, action);
            this._updateDialogRemainingPrompts();
            this._dialog.activate();
        } catch(err) {
            log("SGFW: Error while creating dialog: "  + err);
        }
    },

    _createNextDialogCallback: function() {
        log("SGFW: Checking for next dialog...");
        try {
            if (this._guids.length > 0 && this._current_guid === null) {
                log("SGFW: Opening next dialog: " + this._guids[0] + " (remaining: " + this._guids.length + ")");
                this._createDialog(this._guids[0]);
            }
            Mainloop.source_remove(this._timeoutId);
            this._timeoutId = null;
        } catch (err) {
            log("SGFW: Error on creating next dialog callback: " + err);
        }
    },

    _updateDialogRemainingPrompts: function() { /*
        if (this._dialog === null) {
            return;
        }
        try {
            let remaining = (this._guids.length - 1);
            /*if (remaining > 0) {
                this._dialog.updateRemainingPrompts(remaining);
            }
        } catch(err) {
            log("SGFW: Error while updating remaining dialogs count: " + err);
        }*/
        return;
    }

/*
    TestPrompt: function(params, invocation) {
        log("SGFW: Test Prompt Requested");
        this.RequestPromptAsync(["Firefox", "firefox", "/usr/bin/firefox-esr", "242.12.111.18", "443", "linux", "2342", "TCP", true, true], nil);
    }
*/
});

