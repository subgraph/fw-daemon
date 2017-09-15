package definitions

func init() {
	add(`RuleEdit`, &defRuleEdit{})
}

type defRuleEdit struct{}

func (*defRuleEdit) String() string {
	return `
<?xml version="1.0" encoding="UTF-8"?>
<!-- Generated with glade 3.20.0 -->
<interface>
  <requires lib="gtk+" version="3.16"/>
  <object class="GtkDialog" id="dialog">
    <property name="can_focus">False</property>
    <property name="title" translatable="yes">Edit Rule</property>
    <property name="type_hint">dialog</property>
    <child internal-child="vbox">
      <object class="GtkBox" id="dialog-vbox1">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="dialog-action_area1">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="cancel_button">
                <property name="label" translatable="yes">Cancel</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="ok_button">
                <property name="label" translatable="yes">Ok</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">False</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkGrid" id="grid1">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="margin_left">12</property>
            <property name="margin_right">12</property>
            <property name="margin_top">12</property>
            <property name="margin_bottom">24</property>
            <property name="row_spacing">24</property>
            <child>
              <object class="GtkLabel" id="label1">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Enter changes for firewall rule below.  The character &lt;b&gt;*&lt;/b&gt; can entered alone into either the &lt;b&gt;host&lt;/b&gt; or &lt;b&gt;port&lt;/b&gt; fields to match any value.
</property>
                <property name="use_markup">True</property>
                <property name="wrap">True</property>
                <property name="max_width_chars">40</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">0</property>
                <property name="width">2</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="path_label">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">True</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkGrid" id="grid2">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="margin_left">12</property>
                <property name="column_spacing">10</property>
                <child>
                  <object class="GtkComboBoxText" id="verb_combo">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="active">0</property>
                    <items>
                      <item id="allow" translatable="yes">Allow</item>
                      <item id="allow_tls" translatable="yes">Allow TLS Only</item>
                      <item id="deny" translatable="yes">Deny</item>
                    </items>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label3">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Connections to &lt;b&gt;host:&lt;/b&gt;</property>
                    <property name="use_markup">True</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkEntry" id="host_entry">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="max_width_chars">34</property>
                    <property name="placeholder_text" translatable="yes">hostname or ip address</property>
                    <signal name="changed" handler="on_host_changed" swapped="no"/>
                  </object>
                  <packing>
                    <property name="left_attach">2</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label4">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">on &lt;b&gt;port:&lt;/b&gt;</property>
                    <property name="use_markup">True</property>
                  </object>
                  <packing>
                    <property name="left_attach">3</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkEntry" id="port_entry">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="max_length">5</property>
                    <property name="width_chars">4</property>
                    <property name="max_width_chars">5</property>
                    <property name="placeholder_text" translatable="yes">Port</property>
                    <signal name="changed" handler="on_port_changed" swapped="no"/>
                    <signal name="insert-text" handler="on_port_insert_text" swapped="no"/>
                  </object>
                  <packing>
                    <property name="left_attach">4</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">3</property>
                <property name="width">2</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="label2">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="margin_left">12</property>
                <property name="margin_right">10</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Path:</property>
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
              <object class="GtkLabel" id="sandbox_title">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">False</property>
                <property name="label" translatable="yes">Sandbox:</property>
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
              <object class="GtkLabel" id="sandbox_label">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="halign">start</property>
                <property name="hexpand">True</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">2</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="1">cancel_button</action-widget>
      <action-widget response="2">ok_button</action-widget>
    </action-widgets>
  </object>
</interface>

`
}
