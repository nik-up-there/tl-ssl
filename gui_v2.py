import time
import socket
import select
import tkinter.ttk as ttk
from tkinter import *
from tkinter.messagebox import askquestion
from threading import Thread

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
import matplotlib.pyplot as plt
import networkx as nx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from equipment_v2 import Equipment

EQUIPMENT_TYPES = ["client", "server"]


def display_cert(cert):
    return '\n'.join([
        'Version : {}'.format(str(cert.version)[str(cert.version).find(".") + 1:]),
        'Serial number : {}'.format(cert.serial_number),
        'Not valid before : {}'.format(cert.not_valid_before),
        'Not valid after : {}'.format(cert.not_valid_after),
        'Subject name : {}'.format(
            str(cert.subject)[str(cert.subject).find("=") + 1:str(cert.subject).find(")")]),
        'Issuer name : {}'.format(
            str(cert.issuer)[str(cert.issuer).find("=") + 1:str(cert.issuer).find(")")]),
        'Signature algorithm : {}'.format(cert.signature_algorithm_oid),
        '\n\n'
    ])


class Interface(Frame):
    def __init__(self, window, id_equipment, auto=False):
        Frame.__init__(self, window, width=900, height=900)
        self.__e = Equipment(id_equipment=id_equipment)

        # Button creation:
        self.but_new_equipment = Button(window, text='New equipment', command=self.click_new_equipment)
        but_insert = Button(window, text='Insert', command=lambda: self.click_insert(mode='insert'))
        but_sync = Button(window, text='Sync', command=lambda: self.click_insert(mode='sync'))
        but_info = Button(window, text='Information', command=self.click_info)
        but_CA = Button(window, text='CA', command=self.click_CA)
        but_DA = Button(window, text='DA', command=self.click_DA)

        # New equipment
        if not auto:
            self.txt_equipment_type = Label(window, text='Type of this equipment', wraplength=70)
            self.equipment_type = ttk.Combobox(window, values=EQUIPMENT_TYPES)
            self.equipment_type.current(0)

        # Connection port:
        self.txt_port = Label(window, text='Port', width=10)
        self.port = Entry(window)
        self.port.insert(0, '1110')

        # Creation of the TextBox and its ScrollBar
        scrollbar = Scrollbar(window)
        self.txt_box = Text(window, height=10, width=60)
        scrollbar.config(command=self.txt_box.yview)
        self.txt_box.config(yscrollcommand=scrollbar.set)

        # Layout :
        but_info.grid(row=2, column=1, sticky='nsew', padx=10, pady=10)
        but_CA.grid(row=3, column=1, sticky='nsew', padx=10, pady=10)
        but_DA.grid(row=4, column=1, sticky='nsew', padx=10, pady=10)
        but_insert.grid(row=7, column=3, sticky='nsew', padx=5, pady=10)
        but_sync.grid(row=7, column=4, sticky='nsew', padx=5, pady=10)
        self.but_new_equipment.grid(row=6, column=4, sticky='nsew', padx=5, pady=10)
        if not auto:
            self.equipment_type.grid(row=6, column=2, sticky='ew', padx=10, pady=10)
            self.txt_equipment_type.grid(row=6, column=1, sticky='nsew')
        self.txt_port.grid(row=7, column=1, padx=10, pady=10)
        self.port.grid(row=7, column=2, sticky='nsew', padx=10, pady=10)
        scrollbar.grid(row=2, column=5, rowspan=3, sticky="nsew")
        self.txt_box.grid(row=2, column=2, rowspan=3, columnspan=3, sticky="nsew")

        # Minimum size of the row
        for row in range(window.grid_size()[1]):
            window.grid_rowconfigure(row, minsize=20)

    def click_info(self):
        self.txt_box.delete("1.0", END)
        self.txt_box.insert(END, display_cert(self.__e.cert()))
        nx.draw_networkx(self.__e.graph(), with_labels=True, node_size=500, edge_color='r')
        plt.title('Network of ()'.format(self.__e.name()))
        plt.show()

    def click_CA(self):
        pass
        # number_of_ca = 'Number of CA : {} \n\n'.format(len(self.__ca))
        # self.txt_box.delete("1.0", END)
        # self.txt_box.insert(END, number_of_ca)
        # if self.__ca:
        #     for ca in self.__ca:
        #         text = self.display_cert(ca['cert'])
        #         self.txt_box.insert(END, text)

    def click_DA(self):
        pass
        # number_of_da = 'Number of DA : {} \n\n'.format(len(self.__da))
        # self.txt_box.delete("1.0", END)
        # self.txt_box.insert(END, number_of_da)
        # if self.__da:
        #     for da in self.__da:
        #         text = self.display_cert(da['cert'])
        #         self.txt_box.insert(END, text)

    def click_new_equipment(self):
        self.but_new_equipment.destroy()
        f = Tk()
        f.title('Equipment {}'.format(self.__id_equipment + 1))
        Interface(window=f, id_equipment=self.__id_equipment + 1).mainloop()

    def click_insert(self, mode):
        pass


f1 = Tk()
f1.title('Equipment {}'.format(1))
Interface(window=f1, id_equipment=1, auto=True).mainloop()
