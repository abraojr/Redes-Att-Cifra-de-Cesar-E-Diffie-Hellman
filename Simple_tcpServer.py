# Bibliotecas necessárias
import json
from socket import *

###################################################################
# Cifra de César com Chave gerada usando Diffie-Hellman em Python #
###################################################################


##################################
# GRUPO                          #
# * Abrão Asterio Junior         #
# * Alexandre Bezerra de Andrade #
# * Daniel Santos de Sousa       #
# * Francisco Tommasi Silveira   #
##################################


# ALICE = CLIENT
# BOB   = SERVER



#### FUNÇÕES ####

##########################################################
# Função para verificar se um número é primo
# N: número a ser verificado
# Retorna True se for primo e False se não for
def ehPrimo(N):
    i = 2

    while i < N:
        R = N % i
        if R == 0:
            print("*ehPrimo:\n**{} não é primo!".format(N))
            return False
        i += 1
    else:
        print("*ehPrimo:\n**{} é primo!".format(N))
        return True
##########################################################


##########################################################
# Função para calcular a chave secreta compartilhada/pública usando Diffie-Hellman (R)
# p: número primo (número maior que 2)
# g: base (número inteiro menor que p)
# chavePrivada: número secreto maior que 1
# Retorna a chave pública (R)
def diffieHellmanR(p, g, chavePrivada):
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
    R = (g ** chavePrivada) % p

    #DEBUG
    print("*Diffie-Hellman:")
    print(f"**R = {R}")

    # Retorna a chave pública (R)
    return R
##########################################################


##########################################################
# Função para calcular a chave privada usando Diffie-Hellman (K)
# p: número primo (número maior que 2)
# chavePublica: chave pública (número aleatório)
# chavePrivada: número secreto maior que 1
# Retorna a chave privada (K)
def diffieHellmanK(p,  chavePublica, chavePrivada):
    intChavePublica = int(chavePublica)
    # Checa se p e g são primos
    if not ehPrimo(p) or not ehPrimo(g):
        raise ValueError("p e g devem ser primos!")
    # Checa se p é maior que 2 e g é maior que 1
    if p < 2 or g < 1:
        raise ValueError("p deve ser maior que 2 e g deve ser maior que 1!")
    # Checa se a chave privada é maior que 1
    if intChavePublica < 1:
        raise ValueError("Chave privada deve ser maior que 1!")

    # Calcula a chave privada (K) de Alice e Bob
    K = (intChavePublica ** chavePrivada) % p

    #DEBUG
    print("*Diffie-Hellman:")
    print(f"**K = {K}")

    # Retorna a chave privada (K)
    return K
##########################################################


##########################################################
# Função Cifra de César
# modo: 'E' para cifrar e 'D' para decifrar
# mensagem: mensagem a ser cifrada ou decifrada
# chave: chave para cifrar ou decifrar
# Retorna a mensagem cifrada ou decifrada
def cifraCesar(modo, mensagem, chave):
    # Array para armazenar os caracteres da mensagem
    charArray = []

    # Loop para cada caractere na mensagem e cifra (ou decifra) a mensagem
    for caractere in mensagem:
        if modo == 'D': # Decifra
            charArray.append(chr(ord(caractere) - chave))
        elif modo == 'E': # Cifra
            charArray.append(chr(ord(caractere) + chave))

    # String da mensagem tratada
    mensagemRetorno = ""

    # Concatena os caracteres do array na string da mensagem
    for caract in charArray:
            mensagemRetorno += caract

    #DEBUG
    print(f"*Cifra de Cesar:")
    print(f"**Mensagem recebida:")
    print(f"**Mensagem retornada: {mensagemRetorno}")

    # Retorna a mensagem cifrada ou decifrada
    return mensagemRetorno
##########################################################


##########################################################
# Função para enviar mensagem
# mensagem: mensagem a ser enviada
# p: número primo
# g: base
# privateSecret: chave privada (número aleatório)
# Retorna um objeto JSON com a mensagem cifrada e a chave pública
def envio(mensagem, p, g, privateSecret, sharedSecretReceived):
    # Chave pública (número aleatório)
    sharedSecretSent = diffieHellmanR(p, g, privateSecret)
    k = diffieHellmanK(p, sharedSecretReceived, privateSecret)

    # Cifra a mensagem (adiciona a chave pública no início da mensagem a ser enviada) em format STRING
    #sharedMessageCrypto = f"{sharedSecretSent}{cifraCesar('E', mensagem, k)}"

    # Cifra a mensagem, adiciona a chave pública  e retorna tudo em formato JSON
    sharedMessageCrypto = json.dumps({"MensagemCriptografada": cifraCesar('E', mensagem, k), "Chave": sharedSecretSent})

    #DEBUG
    print("*Envio:")
    print("**Mensagem original: ", mensagem)
    print("**JSON Enviado:", sharedMessageCrypto)

    # Retorna a mensagem cifrada com a chave pública no início
    return sharedMessageCrypto
##########################################################


##########################################################
# Função para receber mensagem
# jsonRecebido: mensagem e chave pública recebida para decifrar
# p: número primo
# privateSecret: chave privada (número aleatório)
# Retorna uma string com a mensagem decifrada
def recebimento(jsonRecebido, p, privateSecret):

    # Recupera o campo Chave do JSON
    sharedSecretReceived = jsonRecebido.get("Chave")

    # Cálculo da chave privada recebida (número aleatório)
    privateSecretReceived = diffieHellmanK(p, sharedSecretReceived, privateSecret)

    # Recupera o campo MensagemCriptografada do JSON
    mensagem = jsonRecebido.get("MensagemCriptografada")

    # Decifra a mensagem recebida
    sharedMessageDecrypto = cifraCesar('D', mensagem, privateSecretReceived)

    #DEBUG
    print("*Recebimento:")
    print("**Mensagem cifrada:", mensagem)
    print("**Mensagem decifrada:", sharedMessageDecrypto)
    print("**Chave R (Recebida):", sharedSecretReceived)
    print("**Chave K:", privateSecretReceived)
    
    # Retorna a mensagem decifrada com a chave privada calculada
    return sharedMessageDecrypto
##########################################################



#### MAIN ####

##########################################################
# Função principal (main)
if __name__ == "__main__":

    # Parâmetros públicos para o Diffie-Hellman
    p = 23 # Número primo aleatório (pode ser qualquer número primo maior que 2)
    g = 11  # Base (pode ser qualquer número inteiro menor que p)

    # Entrada do usuário
    # Chave privada (números aleatórios)
    privateSecret = int(input("Digite a sua chave privada (número aleatório): "))
    
    # Configurações do Server (Bob)
    serverPort = 1300
    serverSocket = socket(AF_INET,SOCK_STREAM)
    serverSocket.bind(("",serverPort))
    serverSocket.listen(7) # o argumento “listen” diz à biblioteca de soquetes que queremos enfileirar no máximo 7 requisições de conexão (normalmente o máximo) antes de recusar começar a recusar conexões externas. Caso o resto do código esteja escrito corretamente, isso deverá ser o suficiente.
    print ("TCP Server\n")
    connectionSocket, addr = serverSocket.accept()

    # Envio da chave pública (R) para o Client (Alice)
    connectionSocket.send(json.dumps({"R": diffieHellmanR(p, g, privateSecret)}).encode())

    # Recebendo mensagem criptografada em formato JSON
    receivedMessage = json.loads(str(connectionSocket.recv(65000),"utf-8"))

    # Decifra a mensagem recebida
    mensagemDecrifada = recebimento(receivedMessage, p, privateSecret)

    # Deixa a mensagem decifrada em caixa alta
    capitalizedSentence = mensagemDecrifada.upper()
    connectionSocket.send(bytes(capitalizedSentence, "utf-8"))
    print ("Sent back to Client (Upper Case): ", capitalizedSentence)

    # Fecha a conexão
    connectionSocket.close()