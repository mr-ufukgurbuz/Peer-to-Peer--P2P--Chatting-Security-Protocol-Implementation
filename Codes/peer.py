# -*- coding: utf-8 -*-
import os, sys, socket, select, threading, thread, time, datetime
from CryptoPeer import *

HELLO_STATUS = False
JOIN_STATUS  = False
LOBY_LEADER_STATUS = False
BUSY_CONDITION = False

allPeersMSKKeyList = {}
MESSAGE_SEQUENCE_NUMBER = 1

threadUserNameLock = threading.Lock()

class Chat_Server(threading.Thread):                                # CHAT SERVER THREAD
    SOCKET_LIST = []

    def __init__(self):
        threading.Thread.__init__(self)
        self.HOST = self.findMyIpAdress()
        self.PORT = 0           # otomatik 1024-65535 arasinda uygun bir porta atama yapar.
        self.server_socket = None
        self.conn = None
        self.serverTextStart = True
        self.hmacKeySender = ""
        self.hmacKeyReceiver = ""
        self.aesKeySender = ""
        self.aesKeyReceiver = ""
        self.ivKeySender = ""
        self.ivKeyReceiver = ""
        self.running = 1

    # findMyIpAdress
    def findMyIpAdress(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host = s.getsockname()[0]
        s.close()
        return host

    def run(self):                                                 # Starts 'CHAT SERVER THREAD'
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.HOST, self.PORT))
        self.server_socket.listen(10)
        self.PORT = self.server_socket.getsockname()[1]

        # add server socket object to the list of readable connections
        self.SOCKET_LIST.append(self.server_socket)

        print ("Chat server started on port " + str(self.PORT))

        while self.running == 1:

            if JOIN_STATUS == True:                                 # JOIN_STATUS control
                # get the list sockets which are ready to be read through select
                # 4th arg, time_out  = 0 : poll and never block
                try:
                    ready_to_read, ready_to_write, in_error = select.select(self.SOCKET_LIST, [], [], 0)

                    for sock in ready_to_read:
                        # a new connection request recieved
                        if sock == self.server_socket:
                            self.conn, self.addr = self.server_socket.accept()
                            self.SOCKET_LIST.append(self.conn)

                            time.sleep(0.5)
                            self.otherUserName = getUserName(self.addr[0], self.addr[1], 'clientPort')

                            if(self.otherUserName != "No_User"):
                                print "Client ('%s') connected\r" % self.otherUserName
                                writeToLogFile(chat_centralClient.userName, "Client ('%s') connected" % self.otherUserName + "\n")

                            if self.serverTextStart and LOBY_LEADER_STATUS:
                                # chat_centralClient.kill()
                                text_input.start()
                                self.serverTextStart = False

                            if (self.otherUserName != "No_User"):
                                self.broadcast(self.server_socket, self.conn, "['%s'] entered our chatting room\n" % self.otherUserName)

                        # a message from a client, not a new connection
                        else:
                            # process data recieved from client,
                            try:
                                receivedMessage = ""
                                # Receiver-side decryption:
                                while True:
                                    # incoming message from remote server, s
                                    packetData = sock.recv(77)

                                    if packetData:
                                        if packetData == "HELLO":            # CHAT_REQUEST
                                            self.helloOperations(sock)
                                            break
                                        else:
                                            userName = getUserName(str(sock.getpeername()[0]), str(sock.getpeername()[1]), 'clientPort')
                                            hmacKeyReceiver = allPeersMSKKeyList[userName]["hmacKeyReceiver"]
                                            aesKeyReceiver  = allPeersMSKKeyList[userName]["aesKeyReceiver"]
                                            ivKeyReceiver   = allPeersMSKKeyList[userName]["ivKeyReceiver"]
                                            senderNonce     = allPeersMSKKeyList[userName]["senderNonce"]


                                            curMessage, curSeq, curType, curLength = verifyFragmentGetMessage(packetData, hmacKeyReceiver, aesKeyReceiver, ivKeyReceiver)
                                            if curType != 1:
                                                receivedMessage += curMessage
                                            else:
                                                receivedMessage += curMessage

                                                # --------------------------------------- Her Iterasyon da IV yi degistir ----------------------------------
                                                if (len(receivedMessage) >= 4):
                                                    allPeersMSKKeyList[userName]["ivKeyReceiver"] = keyDerivation(b"ivKeyReceiver" + receivedMessage[:4], senderNonce, size=16)
                                                else:
                                                    allPeersMSKKeyList[userName]["ivKeyReceiver"] = keyDerivation(b"ivKeyReceiver", senderNonce, size=16)
                                                # ----------------------------------------------------------------------------------------------------------

                                                print '\r' + '[' + str(userName) + '] ' + receivedMessage + '\r'
                                                self.broadcast(self.server_socket, sock, "\r" + '[' + str(userName) + '] ' + receivedMessage)
                                                writeToLogFile(chat_centralClient.userName, '[' + str(userName) + '] ' + receivedMessage + '\n')
                                                break
                                    else:
                                        # peer is offline
                                        if (self.otherUserName != "No_User"):
                                            # print "Offline1 \n"
                                            self.otherUserName = getUserName(str(sock.getpeername()[0]), str(sock.getpeername()[1]), 'clientPort')
                                            self.offlineMessage(sock, self.otherUserName)
                            except:
                                # peer is offline
                                if (self.otherUserName != "No_User"):
                                    #print "Offline2 \n"
                                    self.otherUserName = getUserName(str(sock.getpeername()[0]), str(sock.getpeername()[1]), 'clientPort')
                                    self.offlineMessage(sock, self.otherUserName)
                                continue
                except:
                    continue
            #self.server_socket.close()                             -> Server socket kapatilmasinin duzenlenmesi lazim !!!

     # hello operations
    def helloOperations(self, sock):
        global BUSY_CONDITION
        sock.send("OK")
        if BUSY_CONDITION == True:
            self.conn.send("BUSY")
            time.sleep(0.2)
        else:
            #print "HELLO GELDIIII"
            print (str(self.addr) + " sent you a chat request. \n")
            writeToLogFile(chat_centralClient.userName, (str(self.addr) + " sent you a chat request('HELLO') \n"))
            while True:
                chatChoice = "OK"
                # chatChoice = str(raw_input("Use 'OK' or 'REJECT' to reply: "))
                if chatChoice == "OK":
                    BUSY_CONDITION = True
                    # --------------- LOBYLEADER den CERTIFICATE alma ve ona NONCE-OURCERTIFICATE yollama -------------
                    time.sleep(0.1)
                    # receiving certificateData from the socket.
                    certificateData = sock.recv(2048)  # lobyLeaderCertificateData

                    self.receiverNonce = getRandomValue(12)  # generate nonce
                    self.conn.send(str(self.receiverNonce))
                    time.sleep(0.2)
                    self.conn.send(str(chat_centralClient.ourCertificateData))
                    time.sleep(0.2)
                    senderSignature = sock.recv(1024)  # LobyLeader signure

                    verificationResult = verifySignRSA(self.receiverNonce, senderSignature, getCertificatePublicKey(certificateData))

                    if verificationResult == True:
                        self.conn.send("ACK")
                        #print "ACK"
                        time.sleep(0.1)
                        cipherMSKText = str(sock.recv(1024))  # cipherMSKText -> receiver
                        MSK = decryptRSA(cipherMSKText, chat_centralClient.privateKey)

                        self.hmacKeySender = keyDerivation(MSK[0:8], self.receiverNonce, size=hashes.SHA256().digest_size)
                        self.hmacKeyReceiver = keyDerivation(MSK[4:12], self.receiverNonce, size=hashes.SHA256().digest_size)
                        self.aesKeySender = keyDerivation(MSK[8:16], self.receiverNonce, size=32)
                        self.aesKeyReceiver = keyDerivation(MSK[12:20], self.receiverNonce, size=32)
                        self.ivKeySender = keyDerivation(MSK[16:], self.receiverNonce, size=16)
                        self.ivKeyReceiver = keyDerivation(MSK[20:], self.receiverNonce, size=16)

                        """print self.hmacKeySender
                        print self.hmacKeyReceiver
                        print self.aesKeySender
                        print self.aesKeyReceiver
                        print self.ivKeySender
                        print self.ivKeyReceiver"""

                    else:
                        print "Verification is not provided. \n"

                        # -------------------------------------------------------------------------------------------------
                    self.conn.send("OK")
                    # self.broadcast(self.server_socket, sock, "OK")
                    serverData = str(sock.recv(1024))
                    host, port = serverData.split(",")
                    chat_client.HOST = str(host)
                    chat_client.PORT = int(port)
                    chat_client.ConnectionType = "LobyParticipant"

                    chat_client.start()

                    userName = getUserName(chat_server.server_socket.getsockname()[0],
                                           chat_server.server_socket.getsockname()[1], 'serverPort')
                    clientPort = chat_client.client_socket.getsockname()[1]
                    chat_centralClient.central_client_socket.sendall("clientPortUpdate")
                    time.sleep(0.3)
                    data = str(userName) + "," + str(clientPort)
                    chat_centralClient.central_client_socket.sendall(data)

                    text_input.start()
                    break
                elif chatChoice == "REJECT":
                    # self.broadcast(self.server_socket, sock, "REJECT")
                    self.conn.send("REJECT")
                    break
                else:
                    print ("Wrong input choice. You have to enter only 'OK' or 'REJECT' \n")

    # peer is offline
    def offlineMessage(self, sock, otherUserName):
        # remove the socket that's broken
        if sock in self.SOCKET_LIST:
            self.SOCKET_LIST.remove(sock)

        # at this stage, no data means probably the connection has been broken
        print "Peer ('%s') is offline\n" % otherUserName
        self.broadcast(self.server_socket, sock, "Peer ('%s') is offline\n" % otherUserName)
        writeToLogFile(chat_centralClient.userName, "Peer ('%s') is offline\n" % otherUserName)

    # broadcast chat messages to all connected clients
    def broadcast(self, server_socket, sock, message):
        global allPeersMSKKeyList, MESSAGE_SEQUENCE_NUMBER

        for socket in self.SOCKET_LIST:
            # send the message only to peer
            if socket != server_socket and socket != sock:
                peerHOST = str(socket.getpeername()[0])
                peerPORT = str(socket.getpeername()[1])
                time.sleep(0.2)
                peerName = getUserName(peerHOST, peerPORT, 'clientPort')

                hmacKeySender = allPeersMSKKeyList[peerName]["hmacKeySender"]
                aesKeySender  = allPeersMSKKeyList[peerName]["aesKeySender"]
                ivKeySender   = allPeersMSKKeyList[peerName]["ivKeySender"]
                senderNonce   = allPeersMSKKeyList[peerName]["senderNonce"]
                """hmacKeyReceiver = allPeersMSKKeyList[peerName]["hmacKeyReceiver"]
                aesKeyReceiver = allPeersMSKKeyList[peerName]["aesKeyReceiver"]
                ivKeyReceiver = allPeersMSKKeyList[peerName]["ivKeyReceiver"]"""

                """print  str(peerName) + "\n"
                print hmacKeySender
                print hmacKeyReceiver
                print aesKeySender
                print aesKeyReceiver
                print ivKeySender
                print ivKeyReceiver"""

                arrays = encryptFragments(message, MESSAGE_SEQUENCE_NUMBER, hmacKeySender, aesKeySender, ivKeySender)
                MESSAGE_SEQUENCE_NUMBER = MESSAGE_SEQUENCE_NUMBER + arrays.__len__()

            # --------------------------------------- Her Iterasyon da IV yi degistir ----------------------------------
                if(len(message) >= 4):
                    allPeersMSKKeyList[peerName]["ivKeySender"] = keyDerivation(b"ivKeySender"+message[:4], senderNonce, size=16)
                else:
                    allPeersMSKKeyList[peerName]["ivKeySender"] = keyDerivation(b"ivKeySender", senderNonce, size=16)
            # ----------------------------------------------------------------------------------------------------------
                try:
                    for fragment in arrays:
                        socket.send(str(fragment))
                        time.sleep(0.1)
                    #socket.send(message)
                except:
                    # broken socket connection
                    socket.close()
                    # broken socket, remove it
                    if socket in self.SOCKET_LIST:
                        self.SOCKET_LIST.remove(socket)

    def kill(self):
        self.running = 0

class Chat_Client(threading.Thread):                                    # CHAT CLIENT THREAD
    def __init__(self, HOST, PORT, ConnectionType="LobyParticipant"):
        threading.Thread.__init__(self)
        self.HOST = str(HOST)
        self.PORT = int(PORT)            # baglanilacak server port
        self.ConnectionType = ConnectionType
        self.client_socket = None
        self.serverTextStart = True
        self.running = 1

    def run(self):                                                      # Starts 'CHAT SERVER THREAD'
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.settimeout(2)
        # connect to remote host
        try:
            self.client_socket.connect((self.HOST, self.PORT))
        except:
            print 'Unable to connect'
            sys.exit()

        if(self.ConnectionType == "LobyLeader"):
            try:
                self.client_socket.sendall("HELLO")
            #-----------------------------------------------------------------------------------------------------------
                time.sleep(0.2)
                helloOk = self.client_socket.recv(3)
                #print "HELLO_OK" + str(helloOk) + "\r"
                self.client_socket.sendall(str(chat_centralClient.ourCertificateData))  # Certificate yolla
            #-----------------------------------------------------------------------------------------------------------
            except:
                print "Chat request error ! \n"
                Exception

            # ---------------------- CLIENT tan NONCE ve CERTIFICATE alma, daha sonra nonce kullanarak signature yollama -------------------
            time.sleep(0.2)
            senderNonce = self.client_socket.recv(1024)
            time.sleep(0.1)
            clientCertificate = self.client_socket.recv(2048)
            time.sleep(0.1)
            signature = signWithRSA(senderNonce, chat_centralClient.privateKey)
            self.client_socket.sendall(str(signature))
            ack = self.client_socket.recv(1024)

            if (ack == "ACK"):

                peerUserName = getUserName(self.client_socket.getpeername()[0], self.client_socket.getpeername()[1], 'serverPort')

                MSK = getRandomValue(32)            # generate Master Secret Key

                hmacKeySender = keyDerivation(MSK[0:8], senderNonce, size=hashes.SHA256().digest_size)
                hmacKeyReceiver = keyDerivation(MSK[4:12], senderNonce, size=hashes.SHA256().digest_size)
                aesKeySender = keyDerivation(MSK[8:16], senderNonce, size=32)
                aesKeyReceiver = keyDerivation(MSK[12:20], senderNonce, size=32)
                ivKeySender = keyDerivation(MSK[16:], senderNonce, size=16)
                ivKeyReceiver = keyDerivation(MSK[20:], senderNonce, size=16)

                peerMSKKeys = {"hmacKeySender"  : hmacKeySender,
                               "hmacKeyReceiver": hmacKeyReceiver,
                               "aesKeySender"   : aesKeySender,
                               "aesKeyReceiver" : aesKeyReceiver,
                               "ivKeySender"    : ivKeySender,
                               "ivKeyReceiver"  : ivKeyReceiver,
                               "senderNonce"    : senderNonce}

                allPeersMSKKeyList[peerUserName] = peerMSKKeys

                """print self.hmacKeySender
                print self.hmacKeyReceiver
                print self.aesKeySender
                print self.aesKeyReceiver
                print self.ivKeySender
                print self.ivKeyReceiver"""

                cipherMSKText = encryptRSA(MSK, getCertificatePublicKey(clientCertificate))        # cipherMSKText -> sender
                self.client_socket.sendall(str(cipherMSKText))

                print ("ACK -> '" + peerUserName + "'\r")
            else:
                print "Ack gelmedi hata aldin bilgin ola babos !!!"
            # ------------------------------------------------------------------------------------------------------------------------------

            response = ""
            while True:
                try:
                    response = self.client_socket.recv(1024)
                    break
                except:
                    continue

            if(response == "OK"):                   # Response is 'OK'
                global BUSY_CONDITION
                BUSY_CONDITION = True
                print ("OK -> '" + peerUserName + "'\n")
                writeToLogFile(chat_centralClient.userName, "\nOK -> " + str(self.client_socket.getpeername()) + "\n")
                serverData = str(chat_server.HOST) + "," + str(chat_server.PORT)
                self.client_socket.sendall(serverData)

            elif(response == "REJECT"):             # Response is 'REJECT'
                print ("REJECT -> '" + peerUserName + "'\r")
                writeToLogFile(chat_centralClient.userName, "\nREJECT -> " + str(self.client_socket.getpeername()) + "\n")
            elif(response == "BUSY"):               # Response is 'BUSY'
                print ("BUSY -> '" + peerUserName + "'\r")
                writeToLogFile(chat_centralClient.userName, "\nBUSY -> " + str(self.client_socket.getpeername()) + "\n")
            else:
                print "Incorrect response data !!! \n"

        else:
            #print "[Me] "
            print "\rConnected to a 'loby'.\n"
            writeToLogFile(chat_centralClient.userName, 'Connected to remote host. You can start sending messages\n')
            while self.running == True:
                # Get the list sockets which are readable
                try:
                    read_sockets, write_sockets, error_sockets = select.select([self.client_socket], [], [], 0)
                    for sock in read_sockets:
                        try:
                            receivedMessage = ""
                            # Receiver-side decryption:
                            while True:
                                # incoming message from remote server, s                            # CLIENT-PEER MESAJ ALMA
                                packetData = sock.recv(77)
                                curMessage, curSeq, curType, curLength = verifyFragmentGetMessage(packetData, chat_server.hmacKeySender, chat_server.aesKeySender, chat_server.ivKeySender)
                                if curType != 1:
                                    receivedMessage += curMessage
                                else:
                                    receivedMessage += curMessage
                                    break

                            print receivedMessage
                            writeToLogFile(chat_centralClient.userName, receivedMessage + '\n')

                        # --------------------------------------- Her Iterasyon da IV yi degistir ----------------------------------
                            if (len(receivedMessage) >= 4):
                                chat_server.ivKeySender = keyDerivation(b"ivKeySender" + receivedMessage[:4],chat_server.receiverNonce, size=16)
                            else:
                                chat_server.ivKeySender = keyDerivation(b"ivKeySender", chat_server.receiverNonce, size=16)
                        # ----------------------------------------------------------------------------------------------------------
                        except:
                            # peer is offline
                            self.lobyOfflineMessage(sock)
                            sys.exit()
                except:
                    continue
                time.sleep(0)

    # lobyLeader is offline
    def lobyOfflineMessage(self, sock):
        lobyLeaderIp, lobyLeaderPort = sock.getpeername()
        # at this stage, no data means probably the connection has been broken
        lobyLeaderName = getUserName(lobyLeaderIp, lobyLeaderPort, 'serverPort')
        print "LobyLeader ('%s') is offline\n" % lobyLeaderName
        writeToLogFile(chat_centralClient.userName, "LobyLeader ('%s') is offline\n" % lobyLeaderName + "\n")
        time.sleep(3)
        sys.exit()

    def kill(self):
        self.running = 0


class Text_Input(threading.Thread):                     # TEXT_INPUT THREAD
    def __init__(self):
        threading.Thread.__init__(self)
        self.hmacKey = ""
        self.aesKey  = ""
        self.ivKey   = ""
        self.running = 1

    def run(self):                                      # Starts 'TEXT_INPUT THREAD'
        time.sleep(1)
        print ("\r-----------------------------------------------------------------------------")
        print ("\t \t \t \t <<< You can start sending messages >>>")
        print ("-----------------------------------------------------------------------------\n")
        global LOBY_LEADER_STATUS, MESSAGE_SEQUENCE_NUMBER

        while self.running == 1:
            text = raw_input('')
            # Sender-side encryption:

            if (LOBY_LEADER_STATUS):
                try:
                    userName = getUserName(chat_server.HOST, chat_server.PORT, 'serverPort')
                    chat_server.broadcast(chat_server.server_socket, chat_server.server_socket, "\r" + '[' + userName + '] ' + text)
                    writeToLogFile(chat_centralClient.userName, '[' + userName + '] ' + text + "\n")
                except:
                    Exception
            else:
                arrays = encryptFragments(text, MESSAGE_SEQUENCE_NUMBER, chat_server.hmacKeyReceiver, chat_server.aesKeyReceiver, chat_server.ivKeyReceiver)
                MESSAGE_SEQUENCE_NUMBER = MESSAGE_SEQUENCE_NUMBER + arrays.__len__()

                # --------------------------------------- Her Iterasyon da IV yi degistir ----------------------------------
                if (len(text) >= 4):
                    chat_server.ivKeyReceiver = keyDerivation(b"ivKeyReceiver" + text[:4], chat_server.receiverNonce, size=16)
                else:
                    chat_server.ivKeyReceiver = keyDerivation(b"ivKeyReceiver", chat_server.receiverNonce, size=16)
                # ----------------------------------------------------------------------------------------------------------

                try:
                    for fragment in arrays:
                        chat_client.client_socket.sendall(str(fragment))
                        time.sleep(0.1)
                    #chat_client.client_socket.sendall(text)
                    writeToLogFile(chat_centralClient.userName, "Me: " + str(text) + "\n")
                except:
                    Exception

            time.sleep(0)

    def kill(self):
        self.running = 0


class Chat_CentralClient(threading.Thread):                 # CENTRAL_CLIENT THREAD
    LOBY_USER_LIST = []

    def __init__(self):
        threading.Thread.__init__(self)
        self.HOST = 'localhost'
        self.PORT_TCP = 4004           # central tcp_port
        self.PORT_UDP = 4008           # central udp_port
        self.central_client_socket = None
        self.CONDITION = True
        self.startTime = 0
        self.endTime = 0
        self.running = 1

    def run(self):                                          # Starts 'CENTRAL_CLIENT THREAD'
        self.central_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.central_client_socket.settimeout(3)

        # connect to central_client_socket_tcp
        try:
            self.central_client_socket.connect((self.HOST, self.PORT_TCP))
        except:
            print 'Unable connection to central server unit'
            sys.exit()

        thread.start_new_thread(self._sayHello, ("helloThread",))

        while self.running == 1:

            while self.CONDITION:
                print ("\n---------------------------------------------------")
                choice = str(raw_input("\rPlease, press '1' for registration, '2' for join: "))
                print ("---------------------------------------------------\n")
                if choice == "1":
                    self._registry()
                    break
                elif choice == "2":
                    self._join()
                    self.CONDITION = False
                    self.startTime = time.time()
                    self.kill()
                    break
                else:
                    print "You entered a wrong choice ! \n "
            time.sleep(0)

    def _registry(self):                                                        # REGISTER OPERATION
        chat_centralClient.central_client_socket.sendall("register")
        print "Please enter your user name and password to register. \n"
        while True:
            self.userName = str(raw_input("UserName: "))
            self.password = str(raw_input("Password: "))

            if( (self.userName != "") and (self.password != "") ):          # daha fazla kontrol eklenebilir

                data = str(self.userName + "," + self.password)
                try:
                    chat_centralClient.central_client_socket.sendall(data)
                    processStatus = chat_centralClient.central_client_socket.recv(1024)

                    if processStatus == "Failure1":
                        print ("There is already a record for this username. Please, enter a new user. \n")
                        continue
                    elif processStatus == "Failure2":
                        print ("Registration failed. Please try again. \n")     # database kayit ekleme sorunu
                        continue
                    elif processStatus == "Success":
                        generateLogFileDirectory(self.userName)  # create user directory

                    # ---------------------------- GENERATE PRIVATE-KEY FILE -------------------------------------------
                        privateKey = generateRSAPrivateKey()
                        privateKeyFileName = str(self.userName) + "\\privateKey.pem"
                        generatePEMKeyFile(privateKeyFileName, privateKey)

                    # ---------------------------- GENERATE CSR FILE ---------------------------------------------------
                        user_Name = unicode(self.userName, 'utf-8')
                        csrObject = generateCSRFile(None, privateKey, user_Name, user_Name)
                        csrContent = csrObject.public_bytes(serialization.Encoding.PEM)

                        chat_centralClient.central_client_socket.sendall(str(csrContent))  # CA' ya CSR yollandi.
                        certificateValidationResult = chat_centralClient.central_client_socket.recv(1024)

                        if (certificateValidationResult == "Certificate_Validation_Failure"):
                            print "Certificate Validation Error !!! \n"
                            sys.exit()
                        else:
                            print "Certificate Validation Successful \n"
                    # --------------------------------------------------------------------------------------------------

                        print ("The registration process is successful. You can 'join' \n")
                        break
                    else:
                        print "Incorrect data for 'register' \n"
                except:
                    print "Data sending error for 'register' \n"
                    Exception

            else:
                print "User Name or password can not be empty. Please try again. \n"

    def _join(self):                                                            # JOIN OPERATION
        chat_centralClient.central_client_socket.sendall("join")
        print "Please enter your user name and password to join. \n"
        while True:
            self.userName = str(raw_input("UserName: "))
            self.password = str(raw_input("Password: "))

            if( (self.userName != "") and (self.password != "") ):          # daha fazla kontrol eklenebilir
                data = str(self.userName + "," + self.password + "," + chat_server.HOST + "," + str(chat_server.PORT))

                try:
                    chat_centralClient.central_client_socket.sendall(data)
                    processStatus = chat_centralClient.central_client_socket.recv(1024)

                    if processStatus == "Failure3":
                        print ("User name or password is incorrect. Please, try again. \n")
                        continue
                    elif processStatus == "Failure4":
                        print ("Join failed. Please try again. \n")         # database kayit ekleme sorunu
                        continue
                    elif processStatus == "Success":
                        global JOIN_STATUS
                        print ("\nThe 'join' process is successful. You can 'search' \n")
                        JOIN_STATUS = True
                        self.PEER_CONDITION = False

                    # ---------------------------- PRIVATE-KEY READING FROM LOCAL ------------------------------------------
                        generateLogFileDirectory(self.userName)         # create user directory
                        privateKeyFileName = str(self.userName) + "\\privateKey.pem"
                        self.privateKey = readPEMPrivateKey(privateKeyFileName)

                    #------------------------------- GET CERTIFICATE -------------------------------------------------------
                        chat_centralClient.central_client_socket.sendall(str(self.userName))
                        time.sleep(0.1)
                        self.ourCertificateData = chat_centralClient.central_client_socket.recv(2048)           # get userCertificate

                        ourCertificateObj = x509.load_pem_x509_certificate(self.ourCertificateData, default_backend())

                        # certificate dogrulama yap
                        certValidationResult = validateCertificate(ourCertificateObj, chat_centralClient.privateKey.public_key())

                        if certValidationResult == True:
                            print "Certificate is validated. \n"
                        else:
                            print "Certificate is not validated ! \n"
                            sys.exit()
                    # ------------------------------------------------------------------------------------------------------

                        global HELLO_STATUS
                        HELLO_STATUS = True
                        while True:
                            print ("\n-----------------------------------------------------------------------------")
                            onlineUserListChoice = str(raw_input("\rPress '1' for 'Online User List', '2' for search, '3' for starting to chat: "))
                            print ("-----------------------------------------------------------------------------\n")
                            if (onlineUserListChoice == "1"):
                                chat_centralClient.central_client_socket.sendall("onlineUserList")
                                time.sleep(0.2)
                                data = str(chat_centralClient.central_client_socket.recv(4096))

                                onlineUserList = data[1:-1].replace("(", "").replace(")", "").replace(",", "").replace("'", "").split(" ")

                                print ("\t\t<<< ONLINE USER LIST >>>\r")
                                print ("----------------------------------------\n")
                                print ("\t UserName    IpAddress    Port\n")

                                iteration = 1
                                userAllInfo = ""
                                for userInfo in onlineUserList:
                                    if (iteration%3) == 0:
                                        userAllInfo = userAllInfo + userInfo + ",   "
                                        print "\t" + userAllInfo
                                        userAllInfo = ""
                                    else:
                                        userAllInfo = userAllInfo + userInfo + ",   "
                                    iteration += 1
                                continue

                            elif (onlineUserListChoice == "2"):
                                otherUserIpAddressAndPortList = self._search()
                                while True:
                                    lobyUserListAddChoice = "Yes"
                                    #lobyUserListAddChoice = str(raw_input("Do you want to add the user to your conversation list? ['Yes', 'No'] "))
                                    if(lobyUserListAddChoice == "Yes"):
                                        self.LOBY_USER_LIST.append(otherUserIpAddressAndPortList)
                                        self.PEER_CONDITION = True
                                        break
                                    elif(lobyUserListAddChoice == "No"):
                                        break
                                    else:
                                        print("Wrong input choice. You have to enter only 'Yes' or 'No' \n")
                                continue
                            elif (onlineUserListChoice == "3"):
                                if(not self.PEER_CONDITION):
                                    break

                                if( len(self.LOBY_USER_LIST) == 0):
                                    print("The number of selected users can not be 'zero'. \n")
                                else:
                                    global LOBY_LEADER_STATUS
                                    LOBY_LEADER_STATUS = True
                                    # Kullanici chat lesme islemini baslat... Bagşanmak istedigi peer lara istek yolla
                                    for otherUserIpAndPort in self.LOBY_USER_LIST:
                                        chat_client = Chat_Client(str(otherUserIpAndPort[0]), int(otherUserIpAndPort[1]), "LobyLeader")
                                        chat_client.start()
                                    break
                            else:
                                print("Wrong input choice. You have to enter only '1' or '2' \n")

                        break
                    else:
                        print "Incorrect data for 'join' \n"
                except:
                    print "Data sending error for 'join' \n"
                    Exception
            else:
                print "User Name or password can not be empty. Please try again. \n"

    def _search(self):                                                      # SEARCH OPERATION
        chat_centralClient.central_client_socket.sendall("search")
        print "Please enter a user name to search. \n"

        otherUserIpAddressAndPortList = []

        while True:
            self.otherUserName = str(raw_input("UserName: "))

            if( self.otherUserName != "" ):          # daha fazla kontrol eklenebilir
                try:
                    chat_centralClient.central_client_socket.sendall(self.otherUserName)
                    processStatus = chat_centralClient.central_client_socket.recv(1024)

                    if processStatus == "Failure5":
                        print ("A user record with this name could NOT be FOUND. Please, enter a other 'userName' \n")
                        continue
                    elif processStatus == "Failure6":
                        print ("'" + self.otherUserName + "' is offline. Please, enter a other 'userName' \n")         # database kayit ekleme sorunu
                        continue
                    elif processStatus == "Success":
                        otherUserIpAddressAndPortData = chat_centralClient.central_client_socket.recv(1024)
                        otherUserIpAddress, otherUserPort = otherUserIpAddressAndPortData.split(',')
                        otherUserIpAddressAndPortList = [otherUserIpAddress, otherUserPort]
                        print ("\nUserIp: " + otherUserIpAddress + "\t Port: " + otherUserPort)
                        break
                    else:
                        print "Incorrect data for 'search' \n"
                except:
                    print "Data sending error for 'search \n'"
                    Exception
            else:
                print "User Name or password can not be empty. Please try again. \n"

        return otherUserIpAddressAndPortList

    def _sayHello(self, threadName):                                        # HELLO OPERATION FOR 'CENTRAL SERVER' [UDP]
        # connect to central_client_socket_udp
        self.central_client_socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while True:
            if(HELLO_STATUS):
                self.endTime = time.time()
                elapsedTime = int(self.endTime - self.startTime)

                if (elapsedTime % 10) == 0:
                    #print "Hello diyomm \n"
                    #userName = getUserName(chat_server.HOST, chat_server.PORT, 'serverPort')
                    data = str(self.userName) + "," + "Hello"
                    self.central_client_socket_udp.sendto(data, (self.HOST, self.PORT_UDP))
                    time.sleep(2)
            time.sleep(0.1)

    def clearLobyUserList(self):
        self.LOBY_USER_LIST = []

    def kill(self):
        self.running = 0

# getUserName from 'CENTRAL SERVER'
def getUserName(userIpAddr, userPort, type):    # type='serverPort' type='clientPort'
    threadUserNameLock.acquire()

    chat_centralClient.central_client_socket.sendall("userName")
    data = str(userIpAddr) + "," + str(userPort) + "," + str(type)
    time.sleep(0.2)
    chat_centralClient.central_client_socket.sendall(data)
    time.sleep(0.1)
    userName = chat_centralClient.central_client_socket.recv(40)

    threadUserNameLock.release()

    if userName == "Failure7":
        return "No_User"
    else:
        return userName

# generateLogFileDirectory into 'LOCAL'
def generateLogFileDirectory(userName):
    #directoryName = "LogFile_" + str(userName)
    directoryName = str(userName)
    try:
        if (not os.path.isdir(directoryName)):
            os.mkdir(directoryName)
    except:
        print "Log file generation error ! \n"

    writeToLogFile(chat_centralClient.userName, "\n\n----------------------------------------------------------------------\n")
    writeToLogFile(chat_centralClient.userName, "\t\t" + getDateTime())
    writeToLogFile(chat_centralClient.userName, "\n----------------------------------------------------------------------\n")

# writeToLogFile into 'LOCAL_FILE'   ->> LOGGING OPERATION
def writeToLogFile(userName, data):
    fileName = str(userName) + "\\" + "LogFile_" + str(userName) + ".txt"
    #fileName = str(userName) + "\\" + str(userName) + ".txt"

    with open(fileName, "a") as f:
        f.write(data)

# getDateTime ->> realTime
def getDateTime():
    _date = datetime.datetime.now()
    date = datetime.datetime.ctime(_date)
    return str(date)

if __name__ == "__main__":                                      # PEER THREAD SERVICES
    chat_centralClient = Chat_CentralClient()
    chat_server = Chat_Server()
    chat_client = Chat_Client("", 0, "LobyParticipant")
    text_input = Text_Input()

    chat_server.start()  # baglanma isteklerini dinler            ** ** ** ** **
    chat_centralClient.start()      # merkezi server ile iletisimi saglar