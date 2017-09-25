const Lang = imports.lang;
const Main = imports.ui.main;
const Meta = imports.gi.Meta;
const Shell = imports.gi.Shell;
const St = imports.gi.St;
const Tweener = imports.ui.tweener;

const Extension = imports.misc.extensionUtils.getCurrentExtension();
const Convenience = Extension.imports.convenience;

const ConnectionMonitor = new Lang.Class({
    Name: 'ConnectionMonitor',

    _init: function() {
        this._settings = Convenience.getSettings();
        this._open = false;
        this.actor = new St.BoxLayout({ style_class: 'connection-monitor',
                                        vertical: true,
                                        visible: false,
                                        reactive: true});
        this._resize();
    },

    install: function() {
        Main.wm.addKeybinding('open-connection-monitor',
                              this._settings,
                              Meta.KeyBindingFlags.NONE,
                              Shell.ActionMode.ALL,
                              Lang.bind(this, this._toggle));
        Main.uiGroup.add_actor(this.actor);
        Main.uiGroup.set_child_below_sibling(this.actor, Main.layoutManager.panelBox);
        log("install ConnectionMonitor")
    },

    remove: function() {
        Main.wm.removeKeybinding('open-connection-monitor');
        Main.uiGroup.remove_actor(this.actor);
        log("remove ConnectionMonitor")
    },

    _toggle: function() {
        if (this._open)
            this.close();
        else
            this.open();
    },

    open: function() {
        if (this._open) {
            return;
        }
        this.actor.show();
        this._open = true;
        Tweener.removeTweens(this.actor);
        Tweener.addTween(this.actor, {
            time: 0.5,
            transition: 'easeOutQuad',
            y: this._targetY
        });
    },

    close: function() {
        if (!this._open) {
            return;
        }
        this._open = false;
        Tweener.removeTweens(this.actor);
        Tweener.addTween(this.actor, {
            time: 0.5,
            transition: 'easeOutQuad',
            y: this._hiddenY,
            onComplete: Lang.bind(this, function() {
                this.actor.hide();
            })
        });
    },

    _queueResize: function() {
        Meta.later_add(Meta.LaterType.BEFORE_REDRAW,
            Lang.bind(this, function() { this._resize(); }));
    },

    _resize: function() {
        let primary = Main.layoutManager.primaryMonitor;
        let myWidth = primary.width * 0.6;
        let availableHeight = primary.height - Main.layoutManager.keyboardBox.height;
        let myHeight = primary.height * 0.5;

        this.actor.x = primary.x + primary.width - myWidth;
        this._hiddenY = primary.y + Main.layoutManager.panelBox.height - myHeight;
        this._targetY = this._hiddenY + myHeight;
        this.actor.y = this._hiddenY;
        this.actor.width = myWidth;
        this.actor.height = myHeight;
    }

});
