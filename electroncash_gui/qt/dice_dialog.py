#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from electroncash.i18n import _
from electroncash import mnemonic

from .util import *
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit

class DiceLayout(QVBoxLayout):
    #options
    is_bip39 = False
    is_ext = False

    def is_correct_dice_input(self,data):
        # Initialize to True.  Set False if not all digits or if not enough digits.
        retval = True
        if len(data) < 100:
            retval = False
            return retval
        for ch in data:
            if not ch in "123456":
                retval = False
        return retval

    def __init__(self, seed=None, title=None, icon=True, msg=None, options=None, is_seed=None, passphrase=None, parent=None, editable=True,
                 derivation=None, seed_type=None):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.options = options or ()
        if title:
            self.addWidget(WWLabel(title))
        self.seed_e = ButtonsTextEdit()
        self.editable = bool(editable)
        self.seed_e.setReadOnly(not self.editable)
        if seed:
            self.seed_e.setText(seed)
        else:
            self.seed_e.setTabChangesFocus(True)
            self.is_seed = is_seed
            self.saved_is_seed = self.is_seed
            self.seed_e.textChanged.connect(self.on_edit)
        self.seed_e.setMaximumHeight(75)
        hbox = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QIcon(":icons/dice.png").pixmap(64))
            logo.setMaximumWidth(60)
            hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        self.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.seed_type_label = QLabel('')
        hbox.addWidget(self.seed_type_label)
        grid_maybe = QGridLayout()  # may not be used if none of the below if expressions evaluates to true, that's ok.
        grid_maybe.setColumnStretch(1, 1)  # we want the right-hand column to take up as much space as it needs.
        grid_row = 0

        self.addStretch(1)
         
    def get_dice(self):
        text = self.seed_e.text()
        assert(len(text)>99)
        seed = mnemonic.Mnemonic('en').make_seed_custom(text)
        text = seed
        return ' '.join(text.split())

    def get_seed(self):
        text = self.seed_e.text()
        return ' '.join(text.split())

    _mnem = None
    def on_edit(self):
        #may_clear_warning = not self.has_warning_message and self.editable
        if not self._mnem:
            # cache the lang wordlist so it doesn't need to get loaded each time.
            # This speeds up seed_type_name and Mnemonic.is_checksum_valid
            self._mnem = mnemonic.Mnemonic('en')
        s = self.get_seed()
        b = self.is_correct_dice_input(s)
        self.parent.next_button.setEnabled(b)

class DiceDialog(WindowModalDialog):

    def __init__(self, parent, seed, passphrase, derivation=None, seed_type=None):
        WindowModalDialog.__init__(self, parent, ('Electron Cash - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title =  _("Your wallet generation seed is:")
        dlayout = DiceLayout(title=title, seed=seed, msg=True, passphrase=passphrase, editable=False, derivation=derivation, seed_type=seed_type)
        vbox.addLayout(dlayout)
        vbox.addLayout(Buttons(CloseButton(self)))
