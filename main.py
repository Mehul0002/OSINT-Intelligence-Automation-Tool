import tkinter as tk
from gui.main_gui import OSINTToolGUI

def main():
    root = tk.Tk()
    app = OSINTToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
