# -*- coding: utf-8 -*-
import os, sys, socket, select, threading, thread, time, sqlite3
from CryptoServer import *

class Peer_TCP_Interface(threading.Thread):                 # MAIN THREAD INTERFACE FOR ALL PEERS
    SOCKET_LIST = []
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.running = 1

    def run(self):                                  # Thread starts
        self.connectToDatabase()
        while self.running == 1:

            try:
                request = str(self.conn.recv(1024))
                #time.sleep(0.3)
                print "\t REQUEST: " + str(request) + "\n"

                if request == "register":                       # Register operation
                    self._registry(self.conn, self.addr)

                elif request == "join":                         # Join operation
                    self._join(self.conn, self.addr)

                elif request == "search":                       # Search operation
                    self._search(self.conn, self.addr)

                elif request == "clientPortUpdate":             # ClientPortUpdate operation
                    userNameAndclientPortData = str(self.conn.recv(1024))
                    userName, clientPort = userNameAndclientPortData.split(",")
                    self.updateClientPort(userName, clientPort)

                elif request == "userName":                     # UserName operation
                    time.sleep(0.1)
                    userIpAddrAndPortData = str(self.conn.recv(1024))
                    print  "data: " + userIpAddrAndPortData + "\n"
                    userIpAddr, userPort, type = userIpAddrAndPortData.split(",")

                    userNameData = self.getUserName(userIpAddr, userPort, type)
                    userName = userNameData.replace("[","").replace("]","").replace("(","").replace(")","").replace("'","").replace(",","")

                    if userName == "":
                        self.sendMessageToPeer(self.conn, "Failure7")
                    else:
                        self.sendMessageToPeer(self.conn, str(userName))

                elif request == "onlineUserList":               # UserList operation
                    self.sendMessageToPeer(self.conn, str(self.getAllOnlineUserRecords()))

                else:
                    print "Wrong centralServer Request -> " + str(request) + "\n"
                    self.sendMessageToPeer(self.conn, "Wrong centralServer Request!")
            except:
                print ("Client (%s, %s) is offline\n" % self.addr)
                break

    # sendMessageToPeer
    def sendMessageToPeer(self, socket, message):
        try:
            socket.send(message)
        except:
            # broken socket connection
            socket.close()

    def _registry(self, conn, addr):                            # REGISTER OPERATION FUNCTION
        while True:
            userNameAndPasswordData = str(conn.recv(1024))

            if not userNameAndPasswordData:
                print '\n userNameAndPasswordData hatasi'
                sys.exit()
            else:
                userName, password = userNameAndPasswordData.split(',')
                records = self.getAllUserNamesAndPasswords()
                recordExistStatus = False

                for record in records:
                    recordUserName = record[0]
                    if(userName == recordUserName):
                        recordExistStatus = True
                        break

                if(recordExistStatus == True):
                    #print ("There is already a record for this username. Please, enter a new user. \n")
                    self.sendMessageToPeer(conn, "Failure1")   # boyle bir kullanici var.
                else:
                    try:        # 'userName' ve 'password' girisi kabul edildi.
                        self.insertNewRegistryRecord(userName, password)
                        self.sendMessageToPeer(conn, "Success")

                    # ------------------------- Get CSR File From Peer, then validate it -------------------------------
                        peerCsrContent = str(conn.recv(1024))
                        peerCsrObject = convertCsrContentToCsrObject(peerCsrContent)

                        csrValidationResult = validateCSRSignature(peerCsrObject)

                    # ------------------ VALIDATION dogru ise PEER icin CERTIFICATE olustur ve DB 'ye kaydet -----------
                        if csrValidationResult == True:
                            peerCertificate = generateCertificateFile(None, peerCsrObject, peerCsrObject.public_key(), caPrivateKey)
                            peerCertificateContent = str(peerCertificate.public_bytes(serialization.Encoding.PEM))
                            self.updateCertificate(userName, peerCertificateContent)
                            self.sendMessageToPeer(conn, "Certificate_Validation_Successful")
                        else:
                            self.sendMessageToPeer(conn, "Certificate_Validation_Failure")  # Ceritificate Validation Error
                    # --------------------------------------------------------------------------------------------------

                        break
                    except:
                        #print ("Registration failed. Please try again. \n")
                        self.sendMessageToPeer(conn, "Failure2")  # database kayit ekleme sorunu
                        continue

    def _join(self, conn, addr):                                # JOIN OPERATION FUNCTION
        while True:
            userNamePasswordIpAddrAndPortData = str(conn.recv(1024))
            if not userNamePasswordIpAddrAndPortData:
                print '\n userNamePasswordIpAddrAndPortData hatasi'
                sys.exit()
            else:
                userName, password, ipAddr, port = userNamePasswordIpAddrAndPortData.split(',')
                records = self.getAllUserNamesAndPasswords()
                userLogin = False

                for record in records:
                    recordUserName = record[0]
                    recordPassword = record[1]
                    if ((userName == recordUserName) and (password == recordPassword)):
                        userLogin = True
                        break

                if (userLogin == True):     # 'userName' ve 'password' girisi kabul edildi.
                    try:
                        self.updateRegistryRecord(userName, ipAddr, port)
                        self.sendMessageToPeer(conn, "Success")

                    # --------------------- PEER lara JOIN esnasinda kendi CERTIFICATE lerini yollama ------------------
                        time.sleep(0.1)
                        userName = str(self.conn.recv(1024))
                        peerCertificateData = self.getCertificate(userName)
                        #print peerCertificateData
                        peerCertificate = peerCertificateData[0][0]
                        #peerCertificate = peerCertificateData.replace("[", "").replace("]", "").replace("(", "").replace(")","").replace("'", "").replace(",", "")
                        self.sendMessageToPeer(self.conn, str(peerCertificate))
                    # --------------------------------------------------------------------------------------------------

                        break
                    except:
                        #print ("Join failed. Please try again. \n")
                        self.sendMessageToPeer(conn, "Failure4")  # database kayit ekleme sorunu
                        continue
                else:
                    #print ("User name or password is incorrect. Please, try again. \n")
                    self.sendMessageToPeer(conn, "Failure3")  # boyle bir kullanici var.

    def _search(self, conn, addr):
        while True:                                             # SEARCH OPERATION FUNCTION
            userName = str(conn.recv(1024))
            if not userName:
                print '\n userName hatasi'
                sys.exit()
            else:
                records = self.getAllUserRecords()
                userOnline = ""
                userIpAddress = "a"
                userPort = 0

                for record in records:
                    recordUserName = record[0]
                    recordStatus = record[1]

                    if ((userName == recordUserName) and (1 == recordStatus)):    # boyle bir kullanici var ve online.
                        userOnline = "True"
                        userIpAddress = record[2]
                        userPort = record[3]
                        break
                    elif ((userName == recordUserName) and (0 == recordStatus)):  # boyle bir kullanici var fakat offline
                        userOnline = "False"
                        break
                    else:                                                         # boyle bir kullanici yok
                        userOnline = "UserNotFound"

                if (userOnline == "True"):          # boyle bir kullanici var ve online.
                    self.sendMessageToPeer(conn, "Success")
                    data = str(userIpAddress + "," + str(userPort))
                    self.sendMessageToPeer(conn, data)
                    break
                elif (userOnline == "False"):       # boyle bir kullanici var fakat offline
                    #print ("User is offline. Please, enter a other 'userName' \n")
                    self.sendMessageToPeer(conn, "Failure6")
                    #break
                else:                               # boyle bir kullanici yok
                    #print ("A user record with this name could not be found. Please, enter a other 'userName' \n")
                    self.sendMessageToPeer(conn, "Failure5")  # boyle bir kullanici kaydi yok
                    #break

    # connectToDatabase
    def connectToDatabase(self):
        self.vt = sqlite3.connect('database.sqlite')
        self.vt.text_factory = str
        self.im = self.vt.cursor()              # 'im' dikkat !!!

    # closeDatabaseConnection
    def closeDatabaseConnection(self):
        self.vt.close()

    # getAllUserNamesAndPasswords from database
    def getAllUserNamesAndPasswords(self):
        self.im = self.vt.cursor()
        self.im.execute("SELECT userName, password FROM USER_LIST")
        records = self.im.fetchall()
        return records

    # getAllUserRecords from database
    def getAllUserRecords(self):
        self.im = self.vt.cursor()
        self.im.execute("SELECT userName, status, ipAddress, port FROM USER_LIST")
        records = self.im.fetchall()
        return records

    # getAllOnlineUserRecords from database
    def getAllOnlineUserRecords(self):
        self.im = self.vt.cursor()
        self.im.execute("SELECT userName, ipAddress, port FROM USER_LIST WHERE status=1")  # , ipAddress, port
        records = self.im.fetchall()
        return records

    # getUserName from database
    def getUserName(self, userIp, userPort, type):
        self.im = self.vt.cursor()
        if str(type) == "serverPort":
            self.im.execute("SELECT userName FROM USER_LIST WHERE ipAddress = ? AND port = ?", [str(userIp), int(userPort)])  # , ipAddress, port
        else:
            self.im.execute("SELECT userName FROM USER_LIST WHERE ipAddress = ? AND clientPort = ?", [str(userIp), int(userPort)])  # , ipAddress, clientPort
        records = self.im.fetchall()
        #print records
        return str(records)

    # insertNewRegistryRecord into database
    def insertNewRegistryRecord(self, userName, password):
        self.im = self.vt.cursor()
        status = 0
        self.im.execute("INSERT INTO USER_LIST (userName, password, status) VALUES(?, ?, ?)", [userName, password, status])
        self.vt.commit()

    # updateRegistryRecord from database
    def updateRegistryRecord(self, userName, ipAddr, port):
        self.im = self.vt.cursor()
        status = 1
        self.im.execute("UPDATE USER_LIST SET status = ? , ipAddress = ? , port = ? WHERE username = ?", [status, ipAddr, port, userName])
        self.vt.commit()

    # updateClientPort from database
    def updateClientPort(self, userName, clientPort):
        self.im = self.vt.cursor()
        self.im.execute("UPDATE USER_LIST SET clientPort = ? WHERE username = ?", [int(clientPort), str(userName)])
        self.vt.commit()

    # updateCertificate from database
    def updateCertificate(self, userName, certificate):
        self.im = self.vt.cursor()
        self.im.execute("UPDATE USER_LIST SET certificate = ? WHERE userName = ?", [str(certificate), str(userName)])
        self.vt.commit()

    # getCertificate from database
    def getCertificate(self, userName):
        self.im = self.vt.cursor()
        self.im.execute("SELECT certificate FROM USER_LIST WHERE userName = ?", [str(userName)])
        records = self.im.fetchall()

        return records

    # kill the thread
    def kill(self):
        self.running = 0

class TCP_Thread(threading.Thread):             # CREATE MAIN THREAD FOR "TCP" OPERATIONS
    SOCKET_LIST = []
    def __init__(self):
        threading.Thread.__init__(self)
        self.HOST = ''
        self.PORT = 4004
        self.server_socket = None
        self.running = 1

    def run(self):                                                              # Run the thread
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.HOST, self.PORT))
        self.server_socket.listen(10)
        # add server socket object to the list of readable connections
        self.SOCKET_LIST.append(self.server_socket)

        print "TCP server started on port " + str(self.PORT) + "\n"

        while 1:
            ready_to_read, ready_to_write, in_error = select.select(self.SOCKET_LIST, [], [], 0)

            for sock in ready_to_read:
                # a new connection request recieved
                if sock == self.server_socket:
                    self.conn, self.addr = self.server_socket.accept()
                    self.SOCKET_LIST.append(self.conn)
                    print "Client (%s, %s) connected" % self.addr
                    thread = Peer_TCP_Interface(self.conn, self.addr)
                    thread.start()

    def kill(self):
        self.running = 0

class UDP_Thread(threading.Thread):                              # CREATE SECOND THREAD FOR "UDP" OPERATIONS
    ONLINE_USER_LIST   = {}

    def __init__(self):
        threading.Thread.__init__(self)
        self.HOST = ''
        self.PORT = 4008
        self.server_socket = None
        self.running = 1

    def run(self):                                              # Starts second thread for 'UDP' operations
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.HOST, self.PORT))

        print "UDP server started on port " + str(self.PORT) + "\n"

        thread.start_new_thread(self.peerOfflineControl, ("controlThread", ))

        while self.running == 1:
            try:
                userNameData = self.server_socket.recv(1024)
                print userNameData
                userName, data = str(userNameData).split(",")

                if data == "Hello":
                    if userName not in self.ONLINE_USER_LIST:
                        # add server socket object to the list of readable connections
                        peerStartTime = time.time()
                        self.ONLINE_USER_LIST[userName] = peerStartTime
                    else:
                        peerCurrentTime = time.time()
                        self.ONLINE_USER_LIST[userName] = peerCurrentTime
                else:
                    print  "Incorrect UDP data \n"
            except:
                print "UDP port listening error \n"

    # connectToDatabase
    def connectToDatabase(self):
        self.vt = sqlite3.connect('database.sqlite')
        self.vt.text_factory = str
        self.im = self.vt.cursor()              # 'im' dikkat !!!

    # closeDatabaseConnection
    def closeDatabaseConnection(self):
        self.vt.close()

    # updatePeerStatus
    def updatePeerStatus(self, userName):
        self.connectToDatabase()
        status = 0
        self.im.execute("UPDATE USER_LIST SET status = ? WHERE username = ?", [status, str(userName)])
        self.vt.commit()
        self.closeDatabaseConnection()

    # peerOfflineControl
    def peerOfflineControl(self, threadName):
        while udpThread.running == 1:
            for name in self.ONLINE_USER_LIST.keys():
                currentTime = time.time()
                elapsedTime = int(currentTime - self.ONLINE_USER_LIST[name])

                if elapsedTime > 15:  # userOffline yap
                    print "Peer is offline -> '" + str(name) + "'\n"
                    try:
                        self.ONLINE_USER_LIST.pop(name)
                    except:
                        print "boyle bir adam zaten yok"
                    self.updatePeerStatus(name)

    def kill(self):
        self.running = 0

if __name__ == "__main__":              # CENTRAL SERVER STARTS SERVICES
    # ----------------------------- GENERATE CA -> PUBLIC-PRIVATE KEY -----------------------
    caPrivateKey = generateRSAPrivateKey()
    caPublicKey  = caPrivateKey.public_key()
    # ---------------------------------------------------------------------------------------

    tcpThread = TCP_Thread()
    udpThread = UDP_Thread()
    tcpThread.start()
    udpThread.start()