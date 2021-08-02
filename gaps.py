#!/usr/bin/python

# Google Apps Passwords Sync for Samba4
# author Johan Johansson johan@baboons.se
# Free to use!

import time
import gapslib
import os.path
import sys

while True:
    gapslib.run()
    time.sleep(60)