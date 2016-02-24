package definitions

func init() {
	add(`Dialog`, &defDialog{})
}

type defDialog struct{}

func (*defDialog) String() string {
	return `
<?xml version="1.0" encoding="UTF-8"?>
<!-- Generated with glade 3.19.0 -->
<interface>
  <requires lib="gtk+" version="3.16"/>
  <object class="GtkWindow" id="window">
    <property name="can_focus">False</property>
    <property name="hexpand">True</property>
    <property name="title" translatable="yes">Firewall Settings</property>
    <property name="default_width">600</property>
    <property name="default_height">400</property>
    <property name="type_hint">dialog</property>
    <child>
      <object class="GtkNotebook" id="notebook">
        <property name="visible">True</property>
        <property name="can_focus">True</property>
        <property name="margin_bottom">5</property>
        <child>
          <object class="GtkGrid" id="grid3">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="margin_left">12</property>
            <property name="margin_right">12</property>
            <property name="margin_top">12</property>
            <property name="margin_bottom">12</property>
            <child>
              <object class="GtkLabel" id="label4">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Firewall Rules</property>
                <property name="xalign">0</property>
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
              <object class="GtkGrid" id="grid4">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="margin_left">12</property>
                <property name="margin_right">12</property>
                <property name="margin_top">8</property>
                <property name="hexpand">True</property>
                <property name="vexpand">True</property>
                <child>
                  <object class="GtkScrolledWindow" id="scrolledwindow">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="hexpand">True</property>
                    <property name="vexpand">True</property>
                    <property name="hscrollbar_policy">never</property>
                    <property name="shadow_type">in</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="position">1</property>
          </packing>
        </child>
        <child type="tab">
          <object class="GtkLabel" id="label2">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="label" translatable="yes">Rules</property>
          </object>
          <packing>
            <property name="position">1</property>
            <property name="tab_fill">False</property>
          </packing>
        </child>
        <child>
          <object class="GtkGrid" id="grid1">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="margin_left">12</property>
            <property name="margin_top">12</property>
            <child>
              <object class="GtkGrid" id="grid2">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="margin_left">12</property>
                <property name="margin_top">8</property>
                <property name="row_spacing">6</property>
                <property name="column_spacing">6</property>
                <child>
                  <object class="GtkLabel" id="label3">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="halign">start</property>
                    <property name="label" translatable="yes">Log Level:</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkComboBoxText" id="level_combo">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="active">0</property>
                    <items>
                      <item id="error" translatable="yes">Error</item>
                      <item id="warning" translatable="yes">Warning</item>
                      <item id="notice" translatable="yes">Notice</item>
                      <item id="info" translatable="yes">Info</item>
                      <item id="debug" translatable="yes">Debug</item>
                    </items>
                    <signal name="changed" handler="on_level_combo_changed" swapped="no"/>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">0</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkCheckButton" id="redact_checkbox">
                    <property name="label" translatable="yes">Remove host names and addresses from logs</property>
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="receives_default">False</property>
                    <property name="xalign">0</property>
                    <property name="draw_indicator">True</property>
                    <signal name="toggled" handler="on_redact_checkbox_toggled" swapped="no"/>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">1</property>
                    <property name="width">2</property>
                  </packing>
                </child>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="label5">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Logging</property>
                <property name="ellipsize">start</property>
                <property name="xalign">0</property>
                <attributes>
                  <attribute name="weight" value="bold"/>
                </attributes>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">0</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="position">1</property>
          </packing>
        </child>
        <child type="tab">
          <object class="GtkLabel" id="label1">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="label" translatable="yes">Options</property>
          </object>
          <packing>
            <property name="position">1</property>
            <property name="tab_fill">False</property>
          </packing>
        </child>
      </object>
    </child>
  </object>
</interface>

`
}
