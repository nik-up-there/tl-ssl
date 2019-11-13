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


def normalize_issuer_name(cert):
    return int(str(cert.issuer)[str(cert.issuer).find("=") + 1:str(cert.issuer).find(")")])


def normalize_subject_name(cert):
    return int(str(cert.subject)[str(cert.subject).find("=") + 1:str(cert.subject).find(")")])


class Interface(Frame):
    def __init__(self, window, id_equipment):
        Frame.__init__(self, window, width=900, height=900)
        self.__id_equipment = id_equipment
        self.__e = Equipment(name=str(id_equipment))
        self.graph = nx.MultiDiGraph()
        self.graph.add_node(id_equipment, cert=self.__e.cert())

        # Button creation:
        self.but_new_equipment = Button(window, text='New equipment', command=self.click_new_equipment)
        but_insert = Button(window, text='Insert', command=lambda: self.click_insert_or_sync(mode='insert'))
        but_sync = Button(window, text='Sync', command=lambda: self.click_insert_or_sync(mode='sync'))
        but_info = Button(window, text='Graph\nInformation', command=self.click_info)
        but_CA = Button(window, text='CA', command=self.click_CA)
        but_DA = Button(window, text='All cert', command=self.click_DA)

        # New equipment
        self.txt_equipment_type = Label(window, text='Type of this equipment', wraplength=70)
        self.equipment_type = ttk.Combobox(window, values=EQUIPMENT_TYPES)
        self.equipment_type.current(0)

        # Connection port:
        self.txt_port = Label(window, text='Port', width=10)
        self.port = Entry(window)
        self.port.insert(0, '11111')

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
        self.txt_box.delete("1.0", END)
        list_neighbors = []
        neighbors = nx.all_neighbors(self.graph, self.__id_equipment)
        for neigh in neighbors:
            # neighbors contains successor and predecessor so we take into account only one of them
            if neigh not in list_neighbors:
                list_neighbors.append(neigh)
                text = self.display_cert(self.graph.get_edge_data(self.__id_equipment, neigh, 0)['cert'])
                self.txt_box.insert(END, text)

        number_of_ca = 'Number of CA : {} \n\n'.format(len(list_neighbors))
        self.txt_box.insert("1.0", number_of_ca)

    def click_DA(self):
        self.txt_box.delete("1.0", END)
        cpt = 0
        # add self cert in da
        for node in self.graph.nodes():
            cpt += 1
            text = self.display_cert(self.graph.nodes[node]['cert'])
            self.txt_box.insert(END, text)
        # add cert in da (including those already in ca)
        for edge in self.graph.edges():
            cpt += 1
            text = self.display_cert(self.graph.get_edge_data(edge[0], edge[1], 0)['cert'])
            self.txt_box.insert(END, text)
        number_of_da = 'Number of DA : {} \n\n'.format(cpt)
        self.txt_box.insert("1.0", number_of_da)

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
            'Signature algorithm : {}'.format('SHA256'
                                              if cert.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.11"
                                              else 'Unknown algorithm'),  # utilisation d'un dico de correspondance
            '\n\n'
        ])
        return text

    def click_new_equipment(self):
        self.but_new_equipment.destroy()
        f = Tk()
        f.title('Equipment {}'.format(self.__id_equipment + 1))
        Interface(window=f, id_equipment=self.__id_equipment + 1).mainloop()

    def click_insert_or_sync(self, mode):
        # preparation de la liste de messages
        port_number = self.port.get()
        if mode == 'insert':
            msg = ['self_cert', self.__e.byte_cert(), 'cert', 'da']
        elif mode == 'sync':
            msg = ['self_cert', self.__e.byte_cert()]
            for node in self.graph.nodes():
                # pour ne pas renvoyer deux fois le self cert
                if self.graph.nodes()[node]['cert'].public_bytes(
                        encoding=serialization.Encoding.PEM) != self.__e.byte_cert():
                    msg.append(self.graph.nodes()[node]['cert'].public_bytes(encoding=serialization.Encoding.PEM))
            msg += [b'end', 'cert', 'da']

        # insertion des certs contenus dans ca U da
        for node in self.graph.nodes():
            cert = self.graph.nodes[node]['cert']
            msg.append(cert.public_bytes(encoding=serialization.Encoding.PEM))
        for edge in self.graph.edges():
            cert = self.graph.get_edge_data(edge[0], edge[1], 0)['cert']
            msg.append(cert.public_bytes(encoding=serialization.Encoding.PEM))
        msg.append(b'end')

        # creation des threads client et serveur
        if self.equipment_type.get() == 'client':
            t = Thread(name='client_thread', target=self.client, args=(int(port_number), msg, mode,))
            t.start()
        elif self.equipment_type.get() == 'server':
            t = Thread(name='server_thread', target=self.server, args=(int(port_number), msg, mode,))
            t.start()

    def insertion_equipment(self, self_cert_received, mode):
        result = 'no'
        issuer = int(self_cert_received['id'])
        if mode == 'insert':
            if len(self.graph.nodes()) > 2:
                question = "Authorize Equipment {} to join our network ?".format(issuer)
            else:
                question = "Accept to join Equipment {}'s network ?".format(issuer)
            result = askquestion('Equipment {} - Connection'.format(self.__id_equipment), question)
        elif mode == 'sync':
            result = 'yes'

        if result == 'yes':
            cert = self.__e.generate_certificate(str(issuer), self_cert_received['cert'].public_key(), 10)
            byte_cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
            if (self.__id_equipment, issuer) in self.graph.edges():
                self.graph.remove_edge(self.__id_equipment, issuer)
            self.graph.add_edge(self.__id_equipment, issuer, cert=cert)
            return byte_cert
        else:
            txt = "No connection established"
            self.txt_box.delete("1.0", END)
            self.txt_box.insert(END, txt)
            return b'end'

    def do_we_know_id(self, byte_cert):
        cert_chain = []
        try:
            byte_cert = byte_cert.encode('utf-8')
        except:
            pass
        cert_to_identify = x509.load_pem_x509_certificate(byte_cert, backend=default_backend())
        # on fait verifier les certificat autosigne que l'on recoit
        self.__e.verify_certif(cert_to_identify, cert_to_identify.public_key())
        issuer_name = normalize_issuer_name(cert_to_identify)

        if issuer_name in self.graph.nodes():
            print('Id {} found in graph of id {}'.format(issuer_name, self.__id_equipment))
            shortest_path = nx.shortest_path(self.graph, source=issuer_name,
                                             target=self.__id_equipment, method='dijkstra')
            for i in range(0, len(shortest_path) - 1):
                cert = self.graph.get_edge_data(shortest_path[i], shortest_path[i + 1], 0)['cert']
                byte_cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
                cert_chain.append(byte_cert)
        else:
            print('Id {} NOT found in graph of id {}'.format(issuer_name, self.__id_equipment))
        return cert_chain

    def server(self, num_port, msg, mode):
        host = ''
        tmp_self_cert_received = None
        main_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_connection.bind((host, num_port))
        main_connection.listen(1)
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
                    # reception message
                    received_msg = client.recv(2048)
                    try:
                        received_msg = received_msg.decode()
                    except:
                        pass
                    # handle if mesage = string -> change state
                    if received_msg == 'stop':
                        print('Id {} received STOP'.format(self.__id_equipment))
                        self.graph.remove_node(self_cert_received['id'])
                        server_finished = True
                        client_finished = True
                        client.send('stop'.encode())
                        state = 'end'

                    if received_msg == 'self_cert':
                        state = 'self_cert'
                    elif received_msg == 'proof':
                        state = 'proof'
                        if not equipment_known:
                            cert_to_use = msg[i - 1]
                            self_cert_received = self.verify_self_cert_received(received_msg=tmp_self_cert_received)
                            cert_chain = self.do_we_know_id(byte_cert=cert_to_use)
                            if cert_chain:
                                equipment_known = True
                                msg = [msg[k] for k in range(i)] + ['proof'] + msg[msg.index(b'end') + 1:]
                                for y in range(len(cert_chain)):
                                    msg.insert(i + 1 + y, cert_chain[y])
                    elif received_msg == 'cert':
                        if mode == 'insert':
                            state = 'cert'
                        elif mode == 'sync':
                            if self.verify_proof(cert_chain_other_equipment, self_cert_received, cert_to_use):
                                state = 'cert'
                            else:
                                print('Client not known or unverified')
                                msg.insert(i, 'stop')
                                state = 'end'
                    elif received_msg == 'da':
                        state = 'da'
                    elif received_msg == 'end':
                        client_finished = True
                        state = 'end'
                    # if receive = byte object
                    else:
                        if state == 'self_cert' and mode == 'insert':
                            self_cert_received = self.verify_self_cert_received(received_msg=received_msg)
                        elif state == 'self_cert' and mode == 'sync':
                            if tmp_self_cert_received is None:
                                tmp_self_cert_received = received_msg
                            elif not equipment_known:
                                cert_chain = self.do_we_know_id(byte_cert=received_msg)
                                if cert_chain:
                                    cert_to_use = received_msg
                                    equipment_known = True
                                    msg = [msg[k] for k in range(0, i)] + ['proof'] + msg[msg.index(b'end') + 1:]
                                    for y in range(len(cert_chain)):
                                        msg.insert(i + 1 + y, cert_chain[y])
                                    self_cert_received = self.verify_self_cert_received(received_msg=tmp_self_cert_received)
                        elif state == 'proof':
                            if not cert_chain:
                                msg.insert(i, 'stop')
                            else:
                                cert_chain_other_equipment.append(received_msg)
                        elif state == 'cert':
                            self.state_cert(received_msg=received_msg, self_cert_received=self_cert_received)
                        elif state == 'da':
                            tmp_da.append(received_msg)
                    # send message
                    if server_finished:
                        msg_to_send = 'No more message to send'
                    else:
                        if msg[i] == b'end':
                            server_finished = True
                        msg_to_send = msg[i]

                        if msg_to_send == 'cert':
                            msg.insert(i + 1, self.insertion_equipment(self_cert_received, mode))
                            if msg[i + 1] == b'end':
                                msg_to_send = b'stop'
                                state = 'end'
                    try:
                        msg_to_send = msg_to_send.encode()
                    except:
                        pass
                    client.send(msg_to_send)
                    i += 1

        if tmp_da:
            self.state_da(received_msg=tmp_da)
        print("Closing connections")
        for client in connected_clients:
            client.close()
        main_connection.close()

    def client(self, num_port, msg, mode):
        host = 'localhost'
        tmp_self_cert_received = None
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
            # Sending messages
            if client_finished:
                msg_to_send = 'No more message to send'
            else:
                if msg[i] == b'end':
                    client_finished = True
                msg_to_send = msg[i]
                if msg_to_send == 'cert':
                    msg.insert(i + 1, self.insertion_equipment(self_cert_received, mode))
                    if msg[i + 1] == b'end':
                        msg_to_send = b'stop'
                        state = 'end'

            try:
                msg_to_send = msg_to_send.encode()
            except:
                pass
            connection_with_server.send(msg_to_send)

            # handle messages reception
            received_msg = connection_with_server.recv(2048)
            try:
                received_msg = received_msg.decode()
            except:
                pass

            # change state if receive str
            if received_msg == 'stop':
                print('Id {} received STOP'.format(self.__id_equipment))
                self.graph.remove_node(self_cert_received['id'])
                server_finished = True
                client_finished = True
                connection_with_server.send('stop'.encode())
                state = 'end'

            if received_msg == 'self_cert':
                state = 'self_cert'
            elif received_msg == 'proof':
                state = 'proof'
                if not equipment_known:
                    cert_to_use = msg[i]
                    self_cert_received = self.verify_self_cert_received(received_msg=tmp_self_cert_received)
                    cert_chain = self.do_we_know_id(byte_cert=cert_to_use)
                    if cert_chain:
                        msg = [msg[k] for k in range(i + 1)] + ['proof'] + msg[msg.index(b'end') + 1:]
                        equipment_known = True
                        for y in range(len(cert_chain)):
                            msg.insert(i + 2 + y, cert_chain[y])
            elif received_msg == 'cert':
                if mode == 'insert':
                    state = 'cert'
                elif mode == 'sync':
                    if self.verify_proof(cert_chain_other_equipment, self_cert_received, cert_to_use):
                        state = 'cert'
                    else:
                        print('Server not known or unverified')
                        msg.insert(i+1, 'stop')
                        state = 'end'
            elif received_msg == 'da':
                state = 'da'
            elif received_msg == 'end':
                server_finished = True
                state = 'end'
            # receive data (depends on state)
            else:
                if state == 'self_cert' and mode == 'insert':
                    self_cert_received = self.verify_self_cert_received(received_msg=received_msg)
                elif state == 'self_cert' and mode == 'sync':
                    if tmp_self_cert_received is None:
                        tmp_self_cert_received = received_msg
                    # elif because if the equipment knows the new equipment (and not the other way around),
                    # the new equipment couldn't find a path to equipment
                    elif not equipment_known:
                        cert_chain = self.do_we_know_id(byte_cert=received_msg)
                        if cert_chain:
                            cert_to_use = received_msg
                            equipment_known = True
                            msg = [msg[k] for k in range(i + 1)] + ['proof'] + msg[msg.index(b'end') + 1:]
                            for y in range(len(cert_chain)):
                                msg.insert(i + 2 + y, cert_chain[y])
                            self_cert_received = self.verify_self_cert_received(received_msg=tmp_self_cert_received)
                elif state == 'proof':
                    if not cert_chain:
                        msg.insert(i+1, 'stop')
                    else:
                        cert_chain_other_equipment.append(received_msg)
                elif state == 'cert':
                    self.state_cert(received_msg=received_msg, self_cert_received=self_cert_received)
                elif state == 'da':
                    tmp_da.append(received_msg)
            i += 1
            time.sleep(0.1)  # To give time to server to receive messages

        if tmp_da:
            self.state_da(received_msg=tmp_da)
        print('Closing client')
        connection_with_server.close()

    def verify_proof(self, cert_chain, self_cert_received, byte_cert_of_the_common_id):
        chain_verified = True
        try:
            byte_cert_of_the_common_id = byte_cert_of_the_common_id.encode('utf-8')
        except:
            pass
        # recuperation de la clef publique de l'autorite moyenne
        pubkey_of_the_common_id = x509.load_pem_x509_certificate(byte_cert_of_the_common_id,
                                                                 backend=default_backend()).public_key()
        previous_pubkey = pubkey_of_the_common_id
        # verification de la chaine de certification en extrayant la clef publique du precedent certificat
        for byte_cert in cert_chain:
            cert = x509.load_pem_x509_certificate(byte_cert.encode('utf-8'), backend=default_backend())
            try:
                self.__e.verify_certif(cert, previous_pubkey)
                previous_pubkey = cert.public_key()
            except InvalidSignature:
                print('Certificate invalid {}'.format(cert))
                chain_verified = False
        # verification que la derniere clef publique qui porte sur l'element que l'on veut synchroniser
        try:
            self.__e.verify_certif(self_cert_received['cert'], previous_pubkey)
        except InvalidSignature:
            print('Not the good self pubkey')
            chain_verified = False
        if chain_verified:
            print('Cert chain verified in id {}'.format(self.__id_equipment))
        return chain_verified

    def verify_self_cert_received(self, received_msg):
        # appelle uniquement apres avoir verifier la chaine de certification pour le mode sync
        # pour ne pas ajouter un node en trop
        """
        :param received_msg: receive a self_certificate from another equipment
        - verify it
        - add a node in the graph
        :return: {'id': subject, 'pubkey': pubkey, 'cert': cert}
        """
        cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'), backend=default_backend())
        byte_pubkey = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self_cert_received = None
        try:
            cert.public_key().verify(signature=cert.signature,
                                     data=cert.tbs_certificate_bytes,
                                     padding=padding.PKCS1v15(),
                                     algorithm=cert.signature_hash_algorithm)
            subject = normalize_subject_name(cert)
            if subject not in self.graph.nodes():
                self.graph.add_node(subject, cert=cert)
            else:
                self.graph.nodes()[subject]['cert'] = cert
            self_cert_received = {'id': subject, 'pubkey': byte_pubkey, 'cert': cert}
        except InvalidSignature:
            print('ERROR : Self certificate unverified')
        return self_cert_received

    def state_cert(self, received_msg, self_cert_received):
        """
        :param received_msg: receive a certificate on our public key
        :param self_cert_received: the self cert received from the other equipment
        - verify it
        - add a edge in the graph
        :return:
        """
        cert = x509.load_pem_x509_certificate(received_msg.encode('utf-8'), backend=default_backend())
        subject_pubkey = load_pem_public_key(self_cert_received['pubkey'], backend=default_backend())
        issuer = normalize_issuer_name(cert)
        subject = normalize_subject_name(cert)
        self.__e.verify_certif(cert, subject_pubkey)
        # remove puis add pour remettre un nouveau certif avec nouvelle date de peremption
        if (subject, issuer) in self.graph.edges():
            self.graph.remove_edge(subject, issuer)
        self.graph.add_edge(subject, issuer, cert=cert)

    def state_da(self, received_msg):
        """
        add all graph of the other equipment while verifying every cert we receive with a
        public key we already know in our graph
        :param received_msg:
        :return:
        """
        while received_msg:
            for rcv_msg in received_msg:
                cert_to_check = x509.load_pem_x509_certificate(rcv_msg.encode('utf-8'), backend=default_backend())
                issuer = normalize_issuer_name(cert_to_check)
                subject = normalize_subject_name(cert_to_check)
                # on ajoute noeuds et cert
                if issuer == subject:
                    # si le node n'existe pas dans le graph
                    if subject not in self.graph.nodes():
                        self.__e.verify_certif(cert_to_check, cert_to_check.public_key())
                        self.graph.add_node(subject, cert=cert_to_check)
                    # ou si le noeud existe déjà mais qu'il n'y a pas le certificat associe
                    elif self.graph.nodes()[subject] == {}:
                        self.__e.verify_certif(cert_to_check, cert_to_check.public_key())
                        self.graph.add_node(subject, cert=cert_to_check)
                    received_msg.remove(rcv_msg)
                else: # on travaille sur les edges
                    if (subject, issuer) in self.graph.edges():
                        received_msg.remove(rcv_msg)
                    else:
                        try:  # dans le cas où self.graph.nodes[subject]['cert'] est vide
                            cert = self.graph.nodes[subject]['cert']
                            self.__e.verify_certif(cert_to_check, cert.public_key())
                            self.graph.add_edge(subject, issuer, cert=cert_to_check)
                            received_msg.remove(rcv_msg)
                        except:
                            pass


f1 = Tk()
id_equipment = 1
f1.title('Equipment {}'.format(id_equipment))
Interface(window=f1, id_equipment=id_equipment).mainloop()
