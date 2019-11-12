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

from equipment import Equipment

EQUIPMENT_TYPES = ["client", "server"]


class Interface(Frame):
    def __init__(self, window, id_equipment):
        Frame.__init__(self, window, width=900, height=900)
        self.__id_equipment = id_equipment
        self.__e = Equipment(name=str(id_equipment))
        self.graph = nx.MultiDiGraph()
        self.graph.add_node(id_equipment, cert=self.__e.cert())
        self.__ca = []
        self.__da = []

        self.__da.append({'id': str(self.__id_equipment), 'pubkey': self.__e.pubkey(), 'cert': self.__e.cert()})

        # Button creation:
        self.but_new_equipment = Button(window, text='New equipment', command=self.click_new_equipment)
        but_insert = Button(window, text='Insert', command=lambda: self.click_insert(mode='insert'))
        but_sync = Button(window, text='Sync', command=lambda: self.click_insert(mode='sync'))
        but_info = Button(window, text='Information', command=self.click_info)
        but_CA = Button(window, text='CA', command=self.click_CA)
        but_DA = Button(window, text='DA', command=self.click_DA)

        # New equipment
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
        nx.draw_networkx(self.graph, with_labels=True, node_size=500, edge_color='r')
        plt.title('Network of equipment {}'.format(self.__id_equipment))
        plt.show()

    def click_CA(self):
        number_of_ca = 'Number of CA : {} \n\n'.format(len(self.__ca))
        self.txt_box.delete("1.0", END)
        self.txt_box.insert(END, number_of_ca)
        if self.__ca:
            for ca in self.__ca:
                text = self.display_cert(ca['cert'])
                self.txt_box.insert(END, text)

    def click_DA(self):
        number_of_da = 'Number of DA : {} \n\n'.format(len(self.__da))
        self.txt_box.delete("1.0", END)
        self.txt_box.insert(END, number_of_da)
        if self.__da:
            for da in self.__da:
                text = self.display_cert(da['cert'])
                self.txt_box.insert(END, text)

    def display_cert(self, cert):
        text = '\n'.join([
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
        return text

    def click_new_equipment(self):
        self.but_new_equipment.destroy()
        f = Tk()
        f.title('Equipment {}'.format(self.__id_equipment + 1))
        Interface(window=f, id_equipment=self.__id_equipment + 1).mainloop()

    def click_insert(self, mode):
        port_number = self.port.get()
        if mode == 'insert':
            msg = ['self_cert', self.__e.byte_cert(), 'cert', '']
        else:
            msg = ['self_cert', self.__e.byte_cert(), 'proof', 'cert', '']

        if self.__ca:
            # les CA d'un equipements vont etre les DA d'un autre
            msg.append('ca')
            for ca in self.__ca:
                msg.append(ca['cert'].public_bytes(encoding=serialization.Encoding.PEM))
            for da in self.__da:
                msg.append(da['cert'].public_bytes(encoding=serialization.Encoding.PEM))
        msg.append(b'end')

        if self.equipment_type.get() == 'client':
            t = Thread(name='client_thread', target=self.client, args=(int(port_number), msg, mode,))
            t.start()
        elif self.equipment_type.get() == 'server':
            t = Thread(name='server_thread', target=self.server, args=(int(port_number), msg, mode,))
            t.start()

    def insertion_equipment(self, self_cert_received, mode):
        result = 'no'
        if mode == 'insert':
            result = askquestion('Equipment {} - Connection'.format(self.__id_equipment),
                                 'Authorized Equipment {} to be connected ?'.format(self_cert_received['id']))
        elif mode == 'sync':
            result = 'yes'
        if result == 'yes':
            issuer = str(self_cert_received['id'])
            cert = self.__e.generate_certificate(issuer, self_cert_received['cert'].public_key(), 10)
            byte_cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
            self.graph.add_edge(self.__id_equipment, int(issuer), cert=cert)
            self.__ca.append({'id': self.__id_equipment,
                              'pubkey': self.__e.byte_pubkey(),
                              'cert': cert})
            return byte_cert
        else:
            txt = "No connection established"
            self.txt_box.delete("1.0", END)
            self.txt_box.insert(END, txt)
            return b'end'

    def do_we_know_id(self, byte_cert):
        cert_chain = []
        cert_to_identify = x509.load_pem_x509_certificate(byte_cert.encode('utf-8'), backend=default_backend())
        issuer_name = int(str(cert_to_identify.issuer)[
                          str(cert_to_identify.issuer).find("=") + 1:str(cert_to_identify.issuer).find(")")])

        if issuer_name in self.graph.nodes():
            shortest_path = nx.shortest_path(self.graph, source=self.__id_equipment,
                                             target=issuer_name, method='dijkstra')
            cert_chain.append(self.__e.byte_cert())
            for i in range(len(shortest_path)-1):
                cert = self.graph.get_edge_data(shortest_path[i], shortest_path[i+1], 0)
                cert = cert['cert']
                byte_cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
                cert_chain.append(byte_cert)
        else:
            print('Id {} not found in graph'.format(issuer_name))
        return cert_chain

    def server(self, num_port, msg, mode):
        host = ''
        main_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_connection.bind((host, num_port))
        main_connection.listen(5)
        print("Server listen on port {}".format(num_port))

        connected_clients = []
        i = 0
        state = ''
        self_cert_received = {}
        tmp_da = []
        cert_chain_other_equipment = []
        equipment_known = False
        client_finished = False
        server_finished = False
        while not client_finished or not server_finished:
            connexions_demandees, wlist, xlist = select.select([main_connection], [], [], 0.05)

            for connexion in connexions_demandees:
                connection_with_client, connection_information = connexion.accept()
                connected_clients.append(connection_with_client)

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
                    if received_msg == 'stop':
                        server_finished = True
                        client_finished = True
                        state = 'end'

                    if received_msg == 'self_cert':
                        state = 'self_cert'
                    elif received_msg == 'proof':
                        state = 'proof'
                    elif received_msg == 'cert':
                        if mode == 'insert':
                            state = 'cert'
                        else:
                            if not equipment_known:
                                if not self.verify_proof(cert_chain_other_equipment):
                                    server_finished = True
                                    client_finished = True
                            else:
                                self_cert_received = self.state_self_cert(received_msg=tmp_self_cert_received)
                                state = 'cert'
                    elif received_msg == 'ca':
                        state = 'ca'
                    elif received_msg == 'end':
                        client_finished = True
                        state = 'end'
                    else:
                        if state == 'self_cert' and mode == 'insert':
                            self_cert_received = self.state_self_cert(received_msg=received_msg)
                        elif state == 'self_cert' and mode == 'sync':
                            tmp_self_cert_received = received_msg
                            cert_chain = self.do_we_know_id(byte_cert=received_msg)
                            if cert_chain:
                                equipment_known = True
                                for y in range(len(cert_chain)):
                                    msg.insert(i + 2 + y, cert_chain[y])
                                self_cert_received = self.state_self_cert(received_msg=received_msg)
                            else:
                                msg.insert(i + 2, 'not know')
                        elif state == 'proof':
                            if not cert_chain and received_msg == 'not know':
                                msg.insert(i, 'stop')
                            elif not cert_chain:
                                msg.insert(i, 'not know')
                                cert_chain_other_equipment.append(received_msg)
                        elif state == 'cert':
                            self.state_cert(received_msg=received_msg, self_cert_received=self_cert_received)
                        elif state == 'ca':
                            tmp_da.append(received_msg)

                    if server_finished:
                        msg_to_send = 'No more message to send'
                    else:
                        if msg[i] == b'end':
                            server_finished = True
                        msg_to_send = msg[i]
                        if msg_to_send == 'cert':
                            if mode == 'insert':
                                msg[i + 1] = self.insertion_equipment(self_cert_received, mode)
                                if msg[i+1] == b'end':
                                    msg_to_send = b'end'
                                    state = 'end'
                            else:
                                msg[i + 1] = self.insertion_equipment(self_cert_received, mode)
                    try:
                        msg_to_send = msg_to_send.encode()
                    except:
                        pass
                    client.send(msg_to_send)
                    i += 1
        if tmp_da:
            self.state_ca(received_msg=tmp_da)
        print("Closing connections")
        for client in connected_clients:
            client.close()
        main_connection.close()

    def client(self, num_port, msg, mode):
        host = 'localhost'
        connection_with_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_with_server.connect((host, num_port))
        print("Connexion established with server on port {}".format(num_port))

        self_cert_received = {}
        tmp_da = []
        cert_chain_other_equipment = []
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
                if msg_to_send == 'cert':
                    if mode == 'insert':
                        msg[i + 1] = self.insertion_equipment(self_cert_received, mode)
                        if msg[i + 1] == b'end':
                            msg_to_send = b'end'
                            state = 'end'
                    else:
                        msg[i + 1] = self.insertion_equipment(self_cert_received, mode)

            try:
                msg_to_send = msg_to_send.encode()
            except:
                pass
            # Sending messages
            connection_with_server.send(msg_to_send)
            # print('client send {}'.format(msg_to_send))
            # Received messages
            received_msg = connection_with_server.recv(2048)
            try:
                received_msg = received_msg.decode()
            except:
                pass
            # print('client rcv {}'.format(received_msg))
            if received_msg == 'stop':
                server_finished = True
                client_finished = True
                connection_with_server.send('stop'.encode())
                state = 'end'

            if received_msg == 'self_cert':
                state = 'self_cert'
            elif received_msg == 'proof':
                state = 'proof'
            elif received_msg == 'cert':
                if mode == 'insert':
                    state = 'cert'
                else:
                    # Si l'on connait déjà l'equipement pas besoin de vérifier la chaine de certificat
                    if not equipment_known:
                        if not self.verify_proof(cert_chain_other_equipment):
                            server_finished = True
                            client_finished = True
                    else:
                        self_cert_received = self.state_self_cert(received_msg=tmp_self_cert_received)
                        state = 'cert'
            elif received_msg == 'ca':
                state = 'ca'
            elif received_msg == 'end':
                server_finished = True
                state = 'end'
            else:
                if state == 'self_cert':
                    if mode == 'insert':
                        self_cert_received = self.state_self_cert(received_msg=received_msg)
                    elif mode == 'sync':
                        tmp_self_cert_received = received_msg
                        cert_chain = self.do_we_know_id(byte_cert=received_msg)
                        if cert_chain:
                            equipment_known = True
                            for y in range(len(cert_chain)):
                                msg.insert(i + 2 + y, cert_chain[y])
                            self_cert_received = self.state_self_cert(received_msg=received_msg)
                        else:
                            msg.insert(i + 2, 'not know')
                elif state == 'proof':
                    if not cert_chain and received_msg == 'not know':
                        msg.insert(i, 'stop')
                    elif not cert_chain:
                        msg.insert(i, 'not know')
                        cert_chain_other_equipment.append(received_msg)
                elif state == 'cert':
                    self.state_cert(received_msg=received_msg, self_cert_received=self_cert_received)
                elif state == 'ca':
                    tmp_da.append(received_msg)
            i += 1
            # To give time to server to receive messages
            time.sleep(0.1)

        if tmp_da:
            self.state_ca(received_msg=tmp_da)
        print('Closing client')
        connection_with_server.close()

    def verify_proof(self, cert_chain):
        chain_verified = True
        for byte_cert in cert_chain:
            cert = x509.load_pem_x509_certificate(byte_cert.encode('utf-8'), backend=default_backend())
            if cert.issuer == cert.subject:
                try:
                    self.__e.verify_certif(cert, cert.public_key())
                    previous_pubkey = cert.public_key()
                except InvalidSignature:
                    print('Self certificate invalid')
                    chain_verified = False
            else:
                try:
                    self.__e.verify_certif(cert, previous_pubkey)
                    previous_pubkey = cert.public_key()
                except InvalidSignature:
                    print('Certificate invalid {}'.format(cert))
                    chain_verified = False

        byte_prev_pubkey = previous_pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        if byte_prev_pubkey != self.__e.byte_pubkey():
            print('Not the good self pubkey')
            chain_verified = False
        return chain_verified

    """
    Function state_self_cert:  
        - receive a self_certificate from an other equipment in parameter
        - verify it
        - add a node in the graph 
        Return {'id': subject, 'pubkey': pubkey, 'cert': cert}
    """
    def state_self_cert(self, received_msg):
        cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'), backend=default_backend())
        pubkey = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        try:
            cert.public_key().verify(signature=cert.signature,
                                     data=cert.tbs_certificate_bytes,
                                     padding=padding.PKCS1v15(),
                                     algorithm=cert.signature_hash_algorithm)
            print('Self certificate verified')
        except InvalidSignature:
            print('ERROR : Self certificate unverified')

        subject = int(str(cert.subject)[str(cert.subject).find("=") + 1:str(cert.subject).find(")")])
        self_cert_received = {'id': subject, 'pubkey': pubkey, 'cert': cert}
        if subject not in self.graph.nodes():
            self.graph.add_node(subject, cert=cert)
            self.__da.append(self_cert_received)
        return self_cert_received

    """
        Function state_cert:  
            - receive a certificate on our public key and the sel cert received from the ohter equipment in parameters
            - verify it
            - add a edge in the graph 
    """
    def state_cert(self, received_msg, self_cert_received):
        cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'), backend=default_backend())
        subject_pubkey = load_pem_public_key(self_cert_received['pubkey'], backend=default_backend())
        issuer = int(str(cert.issuer)[str(cert.issuer).find("=") + 1:str(cert.issuer).find(")")])
        subject = int(str(cert.subject)[str(cert.subject).find("=") + 1:str(cert.subject).find(")")])
        self.__e.verify_certif(cert, subject_pubkey)
        self.graph.add_edge(subject, issuer, cert=cert)
        self.__da.append({'id': subject, 'pubkey': subject_pubkey, 'cert': cert})

    def state_ca(self, received_msg):
        while received_msg:
            for rcv_msg in received_msg:
                cert_to_check = x509.load_pem_x509_certificate(rcv_msg.encode('utf-8'), backend=default_backend())
                issuer = int(str(cert_to_check.issuer)[
                             str(cert_to_check.issuer).find("=") + 1:str(cert_to_check.issuer).find(")")])
                subject = int(str(cert_to_check.subject)[
                              str(cert_to_check.subject).find("=") + 1:str(cert_to_check.subject).find(")")])
                already_have_cert = False
                for da in self.__da:
                    if da['cert'].serial_number == cert_to_check.serial_number:
                        already_have_cert = True
                        received_msg.remove(rcv_msg)
                for ca in self.__ca:
                    if ca['cert'].serial_number == cert_to_check.serial_number:
                        already_have_cert = True
                        received_msg.remove(rcv_msg)
                if issuer == subject and not already_have_cert:
                    self.__e.verify_certif(cert_to_check, cert_to_check.public_key())
                    self.__da.append({'id': subject, 'pubkey': cert_to_check.public_key(), 'cert': cert_to_check})
                    self.graph.add_node(subject, cert=cert_to_check)
                    received_msg.remove(rcv_msg)
                elif subject in self.graph.nodes():
                    if not already_have_cert:
                        try:  # dans le cas où self.graph.nodes[subject]['cert'] est vide
                            cert = self.graph.nodes[subject]['cert']
                            self.__e.verify_certif(cert_to_check, cert.public_key())
                            self.__da.append({'id': subject, 'pubkey': cert.public_key(), 'cert': cert_to_check})
                            self.graph.add_edge(subject, issuer, cert=cert_to_check)
                            received_msg.remove(rcv_msg)
                        except:
                            pass


f1 = Tk()
id_equipment = 1
f1.title('Equipment {}'.format(id_equipment))
Interface(window=f1, id_equipment=id_equipment).mainloop()



