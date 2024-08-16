# Bibliotecas necessárias
from socket import *


###################################################################
# Cifra de César com Chave gerada usando Diffie-Hellman em Python #
###################################################################



# ALICE = CLIENT
# BOB   = SERVER



#### FUNÇÕES ####

##########################################################
# Função para verificar se um número é primo
# N: número a ser verificado
def ehPrimo(N):
    i = 2

    while i < N:
        R = N % i
        if R == 0:
            print("{} não é primo!".format(N))
            return False
        i += 1
    else:
        print("{} é primo!".format(N))
        return True
##########################################################


##########################################################
# Função para calcular a chave secreta compartilhada/pública usando Diffie-Hellman
# p: número primo (número maior que 2)
# g: base (número inteiro menor que p)
# chavePrivada: número secreto maior que 1
def diffie_hellman(p, g, chavePrivada):
    # Checa se p e g são primos
    if not ehPrimo(p) or not ehPrimo(g):
        raise ValueError("p e g devem ser primos!")
    # Checa se p é maior que 2 e g é maior que 1
    if p < 2 or g < 1:
        raise ValueError("p deve ser maior que 2 e g deve ser maior que 1!")
    # Checa se a chave privada é maior que 1
    if chavePrivada < 1:
        raise ValueError("Chave privada deve ser maior que 1!")
    
    # Calcula a chave pública (R) de Alice e Bob
    return (g ** chavePrivada) % p
##########################################################


##########################################################
# Função Cifra de César
# modo: 'E' para cifrar e 'D' para decifrar
# mensagem: mensagem a ser cifrada ou decifrada
# chave: chave privada (número aleatório)
def cifraCesar(modo, mensagem, chave):
    # Array para armazenar os caracteres da mensagem
    charArray = []

    # Loop para cada caractere na mensagem e cifra (ou decifra) a mensagem
    for caractere in mensagem:
        if modo == 'D': # Decifra
            charArray.append = [chr(ord(caractere) - chave)]
        elif modo == 'E': # Cifra
            charArray.append = [chr(ord(caractere) + chave)]

    # Retorna a mensagem cifrada ou decifrada
    return str.join(charArray)
##########################################################


##########################################################
# Função para enviar mensagem
# mensagem: mensagem a ser enviada
# p: número primo
# g: base
# privateSecret: chave privada (número aleatório)
def envio(mensagem, p, g, privateSecret):
    # Chave pública (número aleatório)
    sharedSecretSent = diffie_hellman(p, g, privateSecret)

    # Cifra a mensagem (adiciona a chave pública no início da mensagem a ser enviada)
    sharedMessageCrypto = str(sharedSecretSent) + cifraCesar('E', mensagem, privateSecret)

    #DEBUG
    print("Mensagem cifrada:", sharedMessageCrypto)
    print("Chave secreta pública:", sharedSecretSent)

    # Retorna a mensagem cifrada com a chave pública no início
    return sharedMessageCrypto
##########################################################


##########################################################
# Função para receber mensagem
# mensagem: mensagem recebida para decifrar
# p: número primo
# sharedSecretReceived: chave pública recebida (número aleatório)
# privateSecret: chave privada (número aleatório)
def recebimento(mensagem, p, sharedSecretReceived, privateSecret):
    # Cálculo da chave privada recebida (número aleatório)
    privateSecretReceived = diffie_hellman(p, sharedSecretReceived, privateSecret)

    # Decifra a mensagem recebida
    sharedMessageDecrypto = cifraCesar('D', mensagem, privateSecretReceived)

    #DEBUG
    print("Mensagem recebida cifrada:", mensagem)
    print("Chave secreta pública recebida:", sharedSecretReceived)
    print("Mensagem recebida decifrada:", sharedMessageDecrypto)
    print("Chave secreta privada calculada:", privateSecretReceived)
    
    # Retorna a mensagem decifrada com a chave privada calculada
    return sharedMessageDecrypto
##########################################################



#### MAIN ####

##########################################################
# Função principal (main)
if __name__ == "__main__":

    # Parâmetros públicos para o Diffie-Hellman
    p = 27 # Número primo aleatório (pode ser qualquer número primo maior que 2)
    g = 11  # Base (pode ser qualquer número inteiro menor que p)

    # Entrada do usuário
    # Chave privada (números aleatórios)
    privateSecret = int(input("Digite a sua chave privada (número aleatório): "))
    
    # Configurações do Server (Bob)
    serverPort = 1300
    serverSocket = socket(AF_INET,SOCK_STREAM)
    serverSocket.bind(("",serverPort))
    serverSocket.listen(5) # o argumento “listen” diz à biblioteca de soquetes que queremos enfileirar no máximo 5 requisições de conexão (normalmente o máximo) antes de recusar começar a recusar conexões externas. Caso o resto do código esteja escrito corretamente, isso deverá ser o suficiente.
    print ("TCP Server\n")
    connectionSocket, addr = serverSocket.accept()

    # Recebendo mensagem criptografada
    receivedMessage = str(connectionSocket.recv(65000),"utf-8")

    # Mensagem com chave pública recebida (número aleatório)
    sharedSecretReceived = int(receivedMessage[0:2])
    sharedMessageCrypto = receivedMessage[2:len(receivedMessage)]

    # Decifra a mensagem recebida
    recebimento(sharedMessageCrypto, p, sharedSecretReceived, privateSecret)

    # Fecha a conexão
    connectionSocket.close()