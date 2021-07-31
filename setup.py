from distutils.core import setup 
import py2exe
from tkinter import Tk, Entry, Label, CENTER, Button, Canvas, PhotoImage, END, Toplevel
from tkinter import messagebox
from functools import partial
#from pathlib import Path
import random,sqlite3, hashlib, string, sqlite3
from os import path
from pyperclip import copy
from plyer import notification
from pathlib import Path

import sys
sys.stderr = sys.stdout

setup(
    options = {'py2exe': {'bundle_files': 1, 'compressed': False, 'includes':['plyer.platforms.win.notification']}},
    windows = [{'script': "Password_generator.py",
    "icon_resources": [(1, "logo.ico")]}],
    zipfile = None,
)