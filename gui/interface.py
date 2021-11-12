from javax.swing import JPanel, JButton, JTextField, JFrame, BorderFactory, JLabel, GroupLayout, JToggleButton, JCheckBox, SwingConstants, JSeparator
from java.awt import BorderLayout, GridLayout, FlowLayout
from java.awt import Dimension, Font, Color

import logging


class Interface:

    def __init__(self, burp_extender):
        self._extender = burp_extender
        self._main_panel = JPanel()
        self._panel = JPanel()

    def get_main_panel(self):
        return self._main_panel

    def draw_tab(self):
        #self._panel.layout = BorderLayout()
        #self._panel.border = BorderFactory.createTitledBorder("Credentials")

        def btn1Click(event):
            self._extender.set_username(usr_txt.getText())
            self._extender.set_password(pwd_txt.getText())
            #btn1.text = "Saved"
            # TODO: set to "Save" when typig into the textbox
            #       set to "Saved" when the button is clicked
            return

        def btn2Click(event):
            if(self._extender.get_enabled()):
                self._extender.set_enabled(False)
                btn2.setSelected(False)
                btn2.text = "Digest Auth is off"
            else:
                self._extender.set_enabled(True)
                btn2.setSelected(True)
                btn2.text = "Digest Auth is on"
            return

        def auto_update_check(event):
            if(nonce_chk.isSelected()):
                logging.debug("auto-update checked")
                self._extender.set_auto_update_nonce(True)
            else:
                logging.debug("auto-update un-checked")
                self._extender.set_auto_update_nonce(False)

        def tools_check(event):
            cmd = event.getActionCommand()
            logging.debug("Toggling: {}".format(cmd))
            if cmd in self._extender.get_tools():
                self._extender.del_tool(cmd)
            else:
                self._extender.add_tool(cmd)
            

        ban_lbl = JLabel("HTTP Digest Authentication")
        ban_fnt = ban_lbl.getFont().getName()
        ban_lbl.setFont(Font(ban_fnt, Font.BOLD, 18))
        ban2_lbl = JLabel("by pyno")
        sep_lbl = JSeparator(SwingConstants.HORIZONTAL)
        sep_pad = JLabel("  ")
		#sep_pad.setBorder(BorderFactory.createEmptyBorder(0,0,7,0))
    
        btn1 = JButton("Save", actionPerformed=btn1Click)

        btn2 = None
        if self._extender.get_enabled():
            btn2 = JToggleButton("Digest Auth is on", actionPerformed=btn2Click)
            btn2.setSelected(True)
        else:
            btn2 = JToggleButton("Digest Auth is off", actionPerformed=btn2Click)
            btn2.setSelected(False)

        usr_lbl = JLabel("Username")
        usr_txt = JTextField(self._extender.get_username())

        pwd_lbl = JLabel("Password")
        pwd_txt = JTextField(self._extender.get_password())

        cred_lbl = JLabel("Credentials")
        cred_fnt = cred_lbl.getFont().getName()
        cred_lbl.setFont(Font(cred_fnt, Font.BOLD, 14))

        nonce_lbl = JLabel("Nonce")
        nonce_fnt = nonce_lbl.getFont().getName()
        nonce_lbl.setFont(Font(nonce_fnt, Font.BOLD, 14))

        nonce_chk = JCheckBox("Auto-update nonce", self._extender.get_auto_update_nonce(), actionPerformed=auto_update_check)
    
        tools_lbl = JLabel("Tools")
        tools_fnt = tools_lbl.getFont().getName()
        tools_lbl.setFont(Font(tools_fnt, Font.BOLD, 14))
        repeater_chk = JCheckBox("Repeater", "Repeater" in self._extender.get_tools(), actionPerformed=tools_check)
        scanner_chk = JCheckBox("Scanner", "Scanner" in self._extender.get_tools(), actionPerformed=tools_check)


        layout = GroupLayout(self._panel)
        self._panel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        hGroup = layout.createParallelGroup(GroupLayout.Alignment.CENTER) 

        hGroup.addComponent(ban_lbl)
        hGroup.addComponent(ban2_lbl)
        hGroup.addComponent(sep_lbl)
        hGroup.addComponent(sep_pad)
        hGroup.addComponent(btn2)
        hGroup.addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(cred_lbl)
                    .addComponent(usr_lbl)
                    .addComponent(pwd_lbl)
                    .addComponent(btn1)
                    .addComponent(nonce_lbl)
                    .addComponent(nonce_chk)
                    .addComponent(tools_lbl)
                    .addComponent(repeater_chk)
                    .addComponent(scanner_chk))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(usr_txt)
                    .addComponent(pwd_txt)))

        layout.setHorizontalGroup(hGroup)
        
        vGroup = layout.createSequentialGroup()
        vGroup.addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(ban_lbl))
                .addGroup(layout.createParallelGroup()
                    .addComponent(ban2_lbl))
                .addGroup(layout.createParallelGroup()
                    .addComponent(sep_lbl))
                .addGroup(layout.createParallelGroup()
                    .addComponent(sep_pad))
                .addGroup(layout.createParallelGroup()
                    .addComponent(btn2))
                .addGroup(layout.createParallelGroup()
                    .addComponent(sep_pad))
                .addGroup(layout.createParallelGroup()
                    .addComponent(cred_lbl))
                .addGroup(layout.createParallelGroup()
                    .addComponent(usr_lbl)
                    .addComponent(usr_txt))
                .addGroup(layout.createParallelGroup()
                    .addComponent(pwd_lbl)
                    .addComponent(pwd_txt))
                .addGroup(layout.createParallelGroup()
                    .addComponent(btn1))
                .addGroup(layout.createParallelGroup()
                    .addComponent(sep_pad))
                .addGroup(layout.createParallelGroup()
                    .addComponent(nonce_lbl))
                .addGroup(layout.createParallelGroup()
                    .addComponent(nonce_chk))
                .addGroup(layout.createParallelGroup()
                    .addComponent(sep_pad))
                .addGroup(layout.createParallelGroup()
                    .addComponent(tools_lbl))
                .addGroup(layout.createParallelGroup()
                    .addComponent(repeater_chk))
                .addGroup(layout.createParallelGroup()
                    .addComponent(scanner_chk)))

        layout.setVerticalGroup(vGroup)

        self._main_panel.add(self._panel)

