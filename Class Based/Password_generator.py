from tkinter import Frame, Tk, Entry, Label, CENTER, Button, Canvas, PhotoImage, END, Toplevel, messagebox
from functools import partial
#from pathlib import Path
import random,sqlite3, hashlib, string
from pyperclip import copy
from plyer import notification

class Main:
    def __init__(self, master):
        frame = Frame(master)