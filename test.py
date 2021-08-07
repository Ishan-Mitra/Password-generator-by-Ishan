import tkinter
import os

def get_info(arg):
	x = tkinter.StringVar()
	x = tfield.get("1.0", "current lineend") # gives an error 'bad text index "linestart"'
	print(x)
	
root = tkinter.Tk()
tfield = tkinter.Text(root)
tfield.pack()
for line in os.popen("iwconfig", 'r'):
	tfield.insert("end", line)
tfield.bind("<Return>", get_info)

root.mainloop()