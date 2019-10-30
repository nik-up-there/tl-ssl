import time
import socket
import select
import tkinter.ttk as ttk
from tkinter import *
from tkinter.messagebox import askquestion
from threading import Thread

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from equipment import Equipment

EQUIPMENT_TYPES = ["client", "server"]


class Interface(Frame):
    def __init__(self, window, id_equipment=1):
        Frame.__init__(self, window, width=900, height=900)
        self.__id_equipment = id_equipment
        self.__e = Equipment(name="Equipment {}".format(id_equipment))
        self.__ca = []
        self.__da = []

        # Button creation:
        self.but_new_equipment = Button(window, text='New equipment', command=self.click_new_equipment)
        but_insert = Button(window, text='Insert', command=self.click_insert)
        but_sync = Button(window, text='Sync', command=self.click_sync)
        but_info = Button(window, text='Informations', command=self.click_info)
        but_CA = Button(window, text='CA', command=self.click_CA)
        but_DA = Button(window, text='DA', command=self.click_DA)

        # New equipment
        self.txt_equipment_type = Label(window, text='Type of this equipment',
                                        wraplength=70)  # voir si retour a la ligne auto géré par Label
        self.equipment_type = ttk.Combobox(window, values=EQUIPMENT_TYPES)
        self.equipment_type.current(0)

        # Connection port:
        self.txt_port = Label(window, text='Port', width=10)
        self.port = Entry(window)
        self.port.insert(0, '111')

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
        cert = self.__e.cert()
        text = self.display_cert(cert)
        self.txt_box.delete("1.0", END)
        self.txt_box.insert(END, text)

    def click_CA(self):
        number_of_ca = 'Number of CA : {} \n\n'.format(len(self.__ca))
        self.txt_box.delete("1.0", END)
        self.txt_box.insert(END, number_of_ca)
        if self.__ca:
            for ca in self.__ca:
                cert = x509.load_pem_x509_certificate(ca['cert'], backend=default_backend())
                text = self.display_cert(cert)
                self.txt_box.insert(END, text)

    def click_DA(self):
        number_of_da = 'Number of DA : {} \n\n'.format(len(self.__da))
        self.txt_box.delete("1.0", END)
        self.txt_box.insert(END, number_of_da)
        if self.__da:
            for da in self.__da:
                cert = x509.load_pem_x509_certificate(da, backend=default_backend())
                text = self.display_cert(cert)
                self.txt_box.insert(END, text)

    def display_cert(self, cert):
        text = '\n'.join([
            'Version : {}'.format(cert.version),
            'Not valid before : {}'.format(cert.not_valid_before),
            'Not valid after : {}'.format(cert.not_valid_after),
            'Public Key : {}'.format(cert.public_key()),
            'Issuer name : {}'.format(
                str(cert.issuer)[str(cert.issuer).find("=") + 1:str(cert.issuer).find(")")]),
            'Subject name : {}'.format(
                str(cert.subject)[str(cert.subject).find("=") + 1:str(cert.subject).find(")")]),
            'Signature algorithm : {}'.format(cert.signature_algorithm_oid),
            '\n\n'
        ])
        return text

    def click_new_equipment(self):
        self.but_new_equipment.destroy()
        f = Tk()
        f.title('Equipment {}'.format(self.__id_equipment + 1))
        Interface(window=f, id_equipment=self.__id_equipment + 1).mainloop()

    def click_insert(self):
        port_number = self.port.get()
        msg = ['id', str(self.__id_equipment), 'pubkey', self.__e.byte_pubkey(), 'cert', '']
        if self.__ca:
            # les CA d'un equipements vont etre les DA d'un autre
            msg.append('ca')
            for ca in self.__ca:
                msg.append(ca['cert'])
        msg.append(b'end')

        if self.equipment_type.get() == 'client':
            t = Thread(name='client_thread', target=self.client, args=(int(port_number), msg, 'insert',))
            t.start()
        elif self.equipment_type.get() == 'server':
            t = Thread(name='server_thread', target=self.server, args=(int(port_number), msg, 'insert',))
            t.start()

    def click_sync(self):
        port_number = self.port.get()
        msg_for_sync = ['id', str(self.__id_equipment), 'pubkey', self.__e.byte_pubkey(), 'proof', '', 'cert', '']
        if self.__ca:
            # les CA d'un equipements vont etre les DA d'un autre
            msg_for_sync.append('ca')
            for ca in self.__ca:
                msg_for_sync.append(ca['cert'])
        msg_for_sync.append(b'end')

        if self.equipment_type.get() == 'client':
            t = Thread(name='client_thread', target=self.client, args=(int(port_number), msg_for_sync, 'sync',))
            t.start()
        elif self.equipment_type.get() == 'server':
            t = Thread(name='server_thread', target=self.server, args=(int(port_number), msg_for_sync, 'sync',))
            t.start()

    def sync_equipment(self, info_received):
        issuer_name = 'Equipment {}'.format(info_received['id'])
        pubkey_received = info_received['pubkey'].encode('utf-8')
        # verification to know if we already knew the equipment
        res, da = self.do_we_know_id(issuer_name)
        if res:
            print('{} already knew {}'.format(self.__e.name(), issuer_name))
            return da
            """
            issuer_public_key = load_pem_public_key(pubkey_received, backend=default_backend())
            certificate_of_the_other_equipment_in_e = self.__e.generate_certificate(issuer_name, issuer_public_key, 10)
            self.__e.verify_certif(certificate_of_the_other_equipment_in_e, self.__e.pubkey())
            byte_cert = certificate_of_the_other_equipment_in_e.public_bytes(encoding=serialization.Encoding.PEM)
            return byte_cert
            """
        else:
            print("{} don't know {}".format(self.__e.name(), issuer_name))
            return 'not know'

    def insertion_equipment(self, info_received, mode):
        issuer_name = 'Equipment {}'.format(info_received['id'])
        pubkey_received = info_received['pubkey'].encode('utf-8')
        if mode == 'insert':
            result = askquestion('Equipment {} - Connection'.format(self.__id_equipment),
                                 'Authorized Equipment {} to be connected ?'.format(info_received['id']))
        else:
            result = 'yes'
        if result == 'yes':
            issuer_public_key = load_pem_public_key(pubkey_received, backend=default_backend())
            certificate_of_the_other_equipment_in_e = self.__e.generate_certificate(issuer_name, issuer_public_key, 10)
            self.__e.verify_certif(certificate_of_the_other_equipment_in_e, self.__e.pubkey())
            byte_cert = certificate_of_the_other_equipment_in_e.public_bytes(encoding=serialization.Encoding.PEM)
            return byte_cert
        else:
            txt = "Connection non établie"
            self.txt_box.delete("1.0", END)
            self.txt_box.insert(END, txt)
            return b'end'

    def do_we_know_id(self, issuer_name):
        res = False
        byte_cert = ''
        for da in self.__da:
            cert = x509.load_pem_x509_certificate(da, backend=default_backend())
            cert_subject = str(cert.subject)[str(cert.subject).find("=") + 1:str(cert.subject).find(")")]
            if issuer_name == cert_subject:
                res = True
                byte_cert = da
        for ca in self.__ca:
            cert = x509.load_pem_x509_certificate(ca['cert'], backend=default_backend())
            cert_subject = str(cert.subject)[str(cert.subject).find("=") + 1:str(cert.subject).find(")")]
            if issuer_name == cert_subject:
                res = True
                byte_cert = ca['cert']
        return res, byte_cert

    def server(self, num_port, msg, mode):
        host = ''
        main_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_connection.bind((host, num_port))
        main_connection.listen(5)
        print("Le serveur écoute à présent sur le port {}".format(num_port))

        connected_clients = []
        i = 0
        state = ''
        info_received = {}
        equipment_known = False
        client_finished = False
        server_finished = False
        while client_finished == False or server_finished == False:
            connexions_demandees, wlist, xlist = select.select([main_connection], [], [], 0.05)

            for connexion in connexions_demandees:
                connexion_avec_client, infos_connexion = connexion.accept()
                connected_clients.append(connexion_avec_client)

            try:
                clients_a_lire, wlist, xlist = select.select(connected_clients, [], [], 0.05)
            except select.error:
                pass
            else:
                for client in clients_a_lire:
                    received_msg = client.recv(2048)
                    try:
                        received_msg = received_msg.decode()
                    except:
                        pass

                    if received_msg == 'id':
                        state = 'id'
                    elif received_msg == 'pubkey':
                        state = 'pubkey'
                    elif received_msg == 'proof':
                        state = 'proof'
                    elif received_msg == 'cert':
                        if not equipment_known and mode == 'sync':
                            server_finished = True
                            client_finished = True
                        else:
                            state = 'cert'
                    elif received_msg == 'ca':
                        state = 'ca'
                    elif received_msg == 'end':
                        client_finished = True
                        state = 'end'
                    else:
                        if state == 'id':
                            info_received['id'] = received_msg
                        elif state == 'pubkey':
                            info_received['pubkey'] = received_msg
                        elif state == 'proof':
                            if received_msg != 'not know' and received_msg:
                                cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'),
                                                                      backend=default_backend())
                                if self.__e.verify_certif(cert, self.__e.pubkey()):
                                    equipment_known = True
                        elif state == 'cert':
                            cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'),
                                                                  backend=default_backend())
                            pubkey = load_pem_public_key(info_received['pubkey'].encode('utf-8'),
                                                         backend=default_backend())
                            self.__e.verify_certif(cert, pubkey)
                            self.__ca.append({'id': info_received['id'],
                                              'pubkey': info_received['pubkey'],
                                              'cert': received_msg.encode('utf-8')}
                                             )
                        elif state == 'ca':
                            try:
                                # il faudrait trouver un protocole pour recevoir, DA[i] = {Ci, PubCi, CertCi(PubCj)}.
                                # (CertB(PubC1), CertC1(PubC2), …, CertCn(PubCn+1), CertCn+1(PubA))
                                self.__da.append(received_msg.encode('utf-8'))
                                """
                                self.__da.append({'id': id,
                                                  'pubkey': pubkey,
                                                  'cert': received_msg.encode('utf-8')}
                                                 )
                                """
                            except:
                                pass

                    if server_finished:
                        msg_to_send = 'No more message to send'
                    else:
                        if msg[i] == b'end':
                            server_finished = True
                        msg_to_send = msg[i]
                        if msg_to_send == 'proof':
                            msg[i + 1] = self.sync_equipment(info_received)
                            if msg[i + 1] != 'not know':
                                equipment_known = True
                        elif msg_to_send == 'cert':
                            if mode == 'insert':
                                msg[i + 1] = self.insertion_equipment(info_received, mode)
                            elif mode == 'sync' and equipment_known is True:
                                msg[i + 1] = self.insertion_equipment(info_received, mode)
                            else:
                                server_finished = True
                                client_finished = True
                    try:
                        msg_to_send = msg_to_send.encode()
                    except:
                        pass
                    client.send(msg_to_send)
                    i += 1

        print("Closing connections")
        for client in connected_clients:
            client.close()
        main_connection.close()

    def client(self, num_port, msg, mode):
        host = 'localhost'
        connection_with_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_with_server.connect((host, num_port))
        print("Connexion established with server on port {}".format(num_port))

        info_received = {}
        state = ''
        client_finished = False
        server_finished = False
        i = 0
        equipment_known = False
        while not client_finished or not server_finished:
            if client_finished:
                msg_to_send = 'No more message to send'
            else:
                if msg[i] == b'end':
                    client_finished = True
                msg_to_send = msg[i]
                if msg_to_send == 'proof':
                    msg[i + 1] = self.sync_equipment(info_received)
                    if msg[i + 1] != 'not know':
                        equipment_known = True
                elif msg_to_send == 'cert':
                    if not equipment_known and mode == 'sync':
                        server_finished = True
                        client_finished = True
                    if mode == 'insert':
                        msg[i + 1] = self.insertion_equipment(info_received, mode)
                    elif mode == 'sync' and equipment_known is True:
                        msg[i + 1] = self.insertion_equipment(info_received, mode)
                    else:
                        server_finished = True
                        client_finished = True

            try:
                msg_to_send = msg_to_send.encode()
            except:
                pass
            # Sending messages
            connection_with_server.send(msg_to_send)

            # Received messages
            received_msg = connection_with_server.recv(2048)
            try:
                received_msg = received_msg.decode()
            except:
                pass
            if received_msg == 'id':
                state = 'id'
            elif received_msg == 'pubkey':
                state = 'pubkey'
            elif received_msg == 'proof':
                state = 'proof'
            elif received_msg == 'cert':
                state = 'cert'
            elif received_msg == 'ca':
                state = 'ca'
            elif received_msg == 'end':
                server_finished = True
                state = 'end'
            else:
                if state == 'id':
                    info_received['id'] = received_msg
                elif state == 'pubkey':
                    info_received['pubkey'] = received_msg
                elif state == 'proof':
                    if '--BEGIN CERTIFICATE--' in received_msg:
                        cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'),
                                                              backend=default_backend())
                        if self.__e.verify_certif(cert, self.__e.pubkey()):
                            equipment_known = True
                elif state == 'cert':
                    cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'), backend=default_backend())
                    pubkey = load_pem_public_key(info_received['pubkey'].encode('utf-8'), backend=default_backend())
                    self.__e.verify_certif(cert, pubkey)
                    self.__ca.append({'id': info_received['id'],
                                      'pubkey': info_received['pubkey'],
                                      'cert': received_msg.encode('utf-8')}
                                     )
                elif state == 'ca':
                    try:
                        self.__da.append(received_msg.encode('utf-8'))
                    except:
                        pass

            i += 1
            # Permettre au serveur de recevoir
            time.sleep(0.1)

        print('Fermeture client')
        connection_with_server.close()


f1 = Tk()
id_equipment = 1
f1.title('Equipment {}'.format(id_equipment))
Interface(window=f1, id_equipment=id_equipment).mainloop()
