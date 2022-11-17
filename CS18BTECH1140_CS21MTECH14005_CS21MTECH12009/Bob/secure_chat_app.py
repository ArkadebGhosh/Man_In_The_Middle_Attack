####### TASK 2 #######
import socket
import ssl, sys
from OpenSSL import crypto
#ipAddr = '172.31.0.3' # IP of bob1
Port = 9003
Buffer = 2048

def Server():
    # Create a server TCP socket 
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', Port) # Socket address of bob1
    ipAddr = socket.gethostbyname('bob1')
    serversock.bind(server_address)
    serversock.listen(2)
    print("Bob listening on IP:", ipAddr, "\n Waiting for Alice to connect......")
    
    # Accept connection from Alice
    client_connection, client_address = serversock.accept()
    
    while(True):
         msg = client_connection.recv(Buffer).decode('UTF-8')
         # If the incoming messagae is chat hello, send chat reply
         if msg == 'chat_hello':
             print("Message from Alice: ", msg)
             client_connection.sendall('chat_reply'.encode('UTF-8'))
        # If the incoming messagae is chat_Starttls, client wants a secure communication over TLS
         elif msg == 'chat_STARTTLS':
             print("Message from Alice: ", msg)
             client_connection.sendall('chat_STARTTLS_ACK'.encode('UTF-8'))
             break   # Need to establish a secure TLS pipe, so wrap the tcp socket to secure TLS pipe
         elif msg == 'chat_close':
             print("Message from Alice: ", msg)
             client_connection.close()
             serversock.close()
             print("TCP Connection closed!")
             exit()
         else: # Unsecure Chat using just TCP (without TLS) ## useful in downgrade attack Task-3
            print("Message from Alice: ", msg)
            msg = input('Enter message to send it to Alice: ')
            client_connection.sendall(msg.encode('UTF-8'))                 
        
    # Load the CA root certificate in the root store
    certificate_store = crypto.X509Store()
    trusted_certificate = open('/usr/local/share/ca-certificates/root.crt','rt').read()
    certificate_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certificate))
    secureClientSocket = ssl.wrap_socket(client_connection, 
                        server_side=True, 
                        ca_certs="./root.crt", 
                        certfile="Task1/bob.crt",
                        keyfile="Task1/bob_private.pem", 
                        cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLS)
    AliceCert = secureClientSocket.getpeercert(binary_form=True)
    
    # Verify Alice's certificate
    try:
        certificate_context = crypto.X509StoreContext(certificate_store, crypto.load_certificate(crypto.FILETYPE_ASN1, AliceCert))
        certificate_context.verify_certificate()
        print('Alice Certificate Verified Succesfully....')
    except Exception as excp:
        print(excp)
        
    print('TLSv1.3 Handshake Completed....')
    print('TLSv1.3 established Succesfully....')
    
    print('#### Secure Chat ######')
    # Secure Chat with ALice using TLSv1.3
    while(True):
        msg = secureClientSocket.recv(Buffer).decode('UTF-8') 
        if msg == 'chat_close': # If client wants to close the connection
            secureClientSocket.close()
            client_connection.close()
            serversock.close()
            print("Closing TLSv1.3 and TCP Connection")
            exit()
        else:
            print('Message from Alice: ', msg)
            msg = input('Enter message to send it to Alice: ')
            secureClientSocket.sendall(msg.encode())
            

        
def Client(serverhostname):
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_ipAdd = socket.gethostbyname(serverhostname)
    server_address = (bob_ipAdd, Port)
    clientsock.connect(server_address)
    
    # Load the CA root certificate in the root store
    certificate_store = crypto.X509Store()
    trusted_certificate = open('/usr/local/share/ca-certificates/root.crt','rt').read()
    certificate_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certificate))
    
     # Alice sends a chat_hello
    clientsock.sendall("chat_hello".encode())
    msg = clientsock.recv(Buffer)
    print("Message from Bob: ", msg.decode())

    # Alice now sends chat_STARTTLS to establish a secure TLS pipe
    clientsock.sendall("chat_STARTTLS".encode())
    msg = clientsock.recv(Buffer)
    
    # If Bob supports TLS
    if msg.decode() == 'chat_STARTTLS_ACK':
        print("Message from Bob: ", msg.decode())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("/usr/local/share/ca-certificates/root.crt")
        context.load_cert_chain(certfile="Task1/alice.crt", keyfile="Task1/alice_private.pem")
        # To establish TLS 1.3, need to exclude all the lower versions of TLS
        context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        secureClientSocket = context.wrap_socket(clientsock)
        BobCert = secureClientSocket.getpeercert(binary_form=True)
        # Verify Bob's certificate
        try:
            certificate_context = crypto.X509StoreContext(certificate_store, crypto.load_certificate(crypto.FILETYPE_ASN1, BobCert))
            certificate_context.verify_certificate()
            print('Bob Certificate Verified Succesfully....')
        except Exception as excp:
            print(excp)
        
        print('TLSv1.3 Handshake Completed....')
        print('TLSv1.3 established Succesfully....')
        print('#### Secure Chat ######')
            
            # Secure chat with Bob, Send and recieve data securely using TLS pipe
        while(True):
            msg = input('Enter message to send it to Bob: ')
            secureClientSocket.sendall(msg.encode())
            if msg == 'chat_close':
                secureClientSocket.close()
                clientsock.close()
                print("Closing TLSv1.3 and TCP Connection")
                exit()
                    
            else:
                msg = secureClientSocket.recv(Buffer).decode('UTF-8')
                print("Message from Bob: ", msg)
                    
                    
    # If Bob does not support TLS, have to do unsecure chat
    elif msg.decode() == 'chat_STARTTLS_NOTSUPPORTED':
         print('TLS not supported by Bob....')
         print('#### Unsecure Chat ######')
            
            # Unsecure chat with Bob, Send and recieve data securely using TLS pipe
         while(True):
            msg = input('Enter message to send it to Bob: ')
            clientsock.sendall(msg.encode())
            if msg == 'chat_close':
                clientsock.close()
                print("Closing TCP Connection")
                exit()             
            else:
                msg = clientsock.recv(Buffer).decode('UTF-8')
                print("Message from Bob: ", msg)
    
    
def main():
    argv = sys.argv
    if (len(argv) == 2 and argv[1] == "-s"):
        Server()
    elif(len(argv) == 3 and argv[1] == "-c"):
        Client(argv[2])
    else:
        print("To start Server, type -s ....")
        print("To start Client, type -c serverhostname ....")
        exit()

main()
