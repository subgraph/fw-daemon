package definitions

func init() {
	add(`RuleNew`, &defRuleNew{})
}

type defRuleNew struct{}

func (*defRuleNew) String() string {
	return `
<?xml version="1.0" encoding="UTF-8"?>
<!-- Generated with glade 3.20.0 -->
<interface>
  <requires lib="gtk+" version="3.16"/>
  <object class="GtkDialog" id="dialog">
    <property name="can_focus">False</property>
    <property name="title" translatable="yes">Edit Rule</property>
    <property name="role">SubgraphFirewallNewRule</property>
    <property name="resizable">False</property>
    <property name="modal">True</property>
    <property name="window_position">center</property>
    <property name="destroy_with_parent">True</property>
    <property name="icon_name">alacarte</property>
    <property name="type_hint">dialog</property>
    <property name="skip_taskbar_hint">True</property>
    <property name="deletable">False</property>
    <property name="startup_id">SubgraphFirewallNewRule</property>
    <child internal-child="vbox">
      <object class="GtkBox" id="dialog-vbox1">
        <property name="can_focus">False</property>
        <property name="halign">center</property>
        <property name="valign">center</property>
        <property name="margin_left">10</property>
        <property name="margin_right">10</property>
        <property name="margin_top">10</property>
        <property name="margin_bottom">10</property>
        <property name="orientation">vertical</property>
        <property name="spacing">5</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="action_btnbox">
            <property name="can_focus">False</property>
            <property name="hexpand">True</property>
            <property name="homogeneous">True</property>
            <property name="layout_style">spread</property>
            <child>
              <object class="GtkButton" id="allow_button">
                <property name="label" translatable="yes">_Allow</property>
                <property name="sensitive">False</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="no_show_all">True</property>
                <property name="use_underline">True</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="cancel_button">
                <property name="label" translatable="yes">_Cancel</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="can_default">True</property>
                <property name="receives_default">True</property>
                <property name="use_underline">True</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="ok_button">
                <property name="label" translatable="yes">_Ok</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="can_default">True</property>
                <property name="receives_default">True</property>
                <property name="use_underline">True</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">2</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">False</property>
            <property name="position">3</property>
          </packing>
        </child>
        <child>
          <object class="GtkComboBoxText" id="verb_combo">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="active">0</property>
            <items>
              <item id="allow" translatable="yes">Allow</item>
              <item id="deny" translatable="yes">Deny</item>
            </items>
            <signal name="changed" handler="on_verb_changed" swapped="no"/>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkGrid" id="grid3">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="row_spacing">5</property>
            <property name="column_spacing">10</property>
            <property name="row_homogeneous">True</property>
            <child>
              <object class="GtkLabel" id="path_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Path:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="sandbox_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Realm:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="uid_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">UID:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">7</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="gid_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">GID:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">8</property>
              </packing>
            </child>
            <child>
              <object class="GtkFileChooserButton" id="path_chooser">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="create_folders">False</property>
                <property name="preview_widget_active">False</property>
                <property name="use_preview_label">False</property>
                <property name="title" translatable="yes">Select Executable Path</property>
                <signal name="file-set" handler="on_path_changed" swapped="no"/>
                <signal name="file-set" handler="on_path_set" swapped="no"/>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="scope_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Scope:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">9</property>
              </packing>
            </child>
            <child>
              <object class="GtkComboBoxText" id="sandbox_combo">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="proto_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Protocol:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">6</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="host_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="tooltip_markup" translatable="yes">The character &lt;b&gt;*&lt;/b&gt; can be use to match any value.</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Host:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">4</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="host_entry">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="tooltip_markup" translatable="yes">The character &lt;b&gt;*&lt;/b&gt; can be use to match any value.</property>
                <property name="width_chars">64</property>
                <property name="max_width_chars">34</property>
                <property name="primary_icon_tooltip_markup" translatable="yes" context="The character * can be use to match any value.">The character &lt;b&gt;*&lt;/b&gt; can be use to match any value.</property>
                <property name="placeholder_text" translatable="yes">Hostname or IP address</property>
                <signal name="changed" handler="on_host_changed" swapped="no"/>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">4</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="port_entry">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="tooltip_markup" translatable="yes">The character &lt;b&gt;*&lt;/b&gt; can be use to match any value.</property>
                <property name="max_length">5</property>
                <property name="width_chars">4</property>
                <property name="max_width_chars">5</property>
                <property name="primary_icon_tooltip_markup" translatable="yes">The character &lt;b&gt;*&lt;/b&gt; can be use to match any value.</property>
                <property name="placeholder_text" translatable="yes">Port</property>
                <signal name="changed" handler="on_port_changed" swapped="no"/>
                <signal name="insert-text" handler="on_port_insert_text" swapped="no"/>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">5</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="port_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="tooltip_markup" translatable="yes">The character &lt;b&gt;*&lt;/b&gt; can be use to match any value.</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Port:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">5</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="sandbox_label">
                <property name="can_focus">False</property>
                <property name="no_show_all">True</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">SANDBOX</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="pid_title">
                <property name="can_focus">False</property>
                <property name="no_show_all">True</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Pid:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">2</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="pid_label">
                <property name="can_focus">False</property>
                <property name="no_show_all">True</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">PID_LABEL</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">2</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="scope_label">
                <property name="can_focus">False</property>
                <property name="no_show_all">True</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">SCOPE_LABEL</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">9</property>
              </packing>
            </child>
            <child>
              <object class="GtkBox">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="homogeneous">True</property>
                <property name="baseline_position">top</property>
                <child>
                  <object class="GtkComboBoxText" id="uid_combo">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="active">0</property>
                    <property name="active_id">-1</property>
                    <items>
                      <item id="-1">Any User</item>
                    </items>
                  </object>
                  <packing>
                    <property name="expand">False</property>
                    <property name="fill">True</property>
                    <property name="position">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkCheckButton" id="uid_checkbox">
                    <property name="label" translatable="yes">Apply</property>
                    <property name="sensitive">False</property>
                    <property name="can_focus">True</property>
                    <property name="receives_default">False</property>
                    <property name="no_show_all">True</property>
                    <property name="xalign">0</property>
                    <property name="draw_indicator">True</property>
                  </object>
                  <packing>
                    <property name="expand">False</property>
                    <property name="fill">True</property>
                    <property name="position">1</property>
                  </packing>
                </child>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">7</property>
              </packing>
            </child>
            <child>
              <object class="GtkBox">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="homogeneous">True</property>
                <child>
                  <object class="GtkComboBoxText" id="gid_combo">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="active">0</property>
                    <property name="active_id">-1</property>
                    <items>
                      <item id="-1">Any Group</item>
                    </items>
                  </object>
                  <packing>
                    <property name="expand">False</property>
                    <property name="fill">True</property>
                    <property name="position">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkCheckButton" id="gid_checkbox">
                    <property name="label" translatable="yes">Apply</property>
                    <property name="sensitive">False</property>
                    <property name="can_focus">True</property>
                    <property name="receives_default">False</property>
                    <property name="no_show_all">True</property>
                    <property name="xalign">0</property>
                    <property name="draw_indicator">True</property>
                  </object>
                  <packing>
                    <property name="expand">False</property>
                    <property name="fill">True</property>
                    <property name="position">1</property>
                  </packing>
                </child>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">8</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="path_entry">
                <property name="sensitive">False</property>
                <property name="can_focus">True</property>
                <property name="no_show_all">True</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="origin_label">
                <property name="can_focus">False</property>
                <property name="no_show_all">True</property>
                <property name="tooltip_markup" translatable="yes">The character &lt;b&gt;*&lt;/b&gt; can be use to match any value.</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Origin:</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">3</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="origin_entry">
                <property name="sensitive">False</property>
                <property name="can_focus">True</property>
                <property name="no_show_all">True</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">3</property>
              </packing>
            </child>
            <child>
              <object class="GtkComboBoxText" id="scope_combo">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="active">0</property>
                <property name="active_id">0</property>
                <items>
                  <item id="2" translatable="yes">Permanent</item>
                  <item id="0" translatable="yes">Session</item>
                  <item id="1" translatable="yes">Process</item>
                  <item id="4" translatable="yes">Once</item>
                  <item id="3" translatable="yes">System</item>
                </items>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">9</property>
              </packing>
            </child>
            <child>
              <object class="GtkBox">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="homogeneous">True</property>
                <child>
                  <object class="GtkComboBoxText" id="proto_combo">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="active">1</property>
                    <property name="active_id">1</property>
                    <items>
                      <item translatable="yes">Any</item>
                      <item id="tcp" translatable="yes">TCP</item>
                      <item id="udp" translatable="yes">UDP</item>
                      <item id="icmp" translatable="yes">ICMP</item>
                    </items>
                    <signal name="changed" handler="on_proto_changed" swapped="no"/>
                  </object>
                  <packing>
                    <property name="expand">False</property>
                    <property name="fill">True</property>
                    <property name="position">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkCheckButton" id="tls_check">
                    <property name="label" translatable="yes">TLS Only</property>
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="receives_default">False</property>
                    <property name="draw_indicator">True</property>
                  </object>
                  <packing>
                    <property name="expand">False</property>
                    <property name="fill">True</property>
                    <property name="position">1</property>
                  </packing>
                </child>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">6</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="padding">5</property>
            <property name="position">1</property>
          </packing>
        </child>
        <child>
          <object class="GtkSeparator">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">2</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="3">allow_button</action-widget>
      <action-widget response="1">cancel_button</action-widget>
      <action-widget response="2">ok_button</action-widget>
    </action-widgets>
  </object>
</interface>

`
}
