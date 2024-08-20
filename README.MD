# Cifra de César com Chave Gerada Usando Diffie-Hellman

Este projeto implementa uma comunicação segura entre um servidor (Bob) e um cliente (Alice) utilizando uma combinação da Cifra de César e o algoritmo de troca de chaves Diffie-Hellman. O sistema permite que Bob e Alice troquem mensagens criptografadas, garantindo a confidencialidade através de uma chave secreta gerada de forma segura.

## 📜 Descrição

O projeto consiste em dois scripts principais:

- **Simple_tcpServer.py**: Implementa o lado do servidor (Bob), responsável por gerar uma chave pública e privada usando Diffie-Hellman, decifrar a mensagem recebida do cliente, e retornar a mensagem em caixa alta.
  
- **Simple_tcpClient.py**: Implementa o lado do cliente (Alice), responsável por gerar sua chave pública e privada, criptografar uma mensagem com a chave secreta e enviar a mensagem para o servidor.

### 🧠 Algoritmos Utilizados

1. **Diffie-Hellman**: Utilizado para troca de chaves segura entre Alice e Bob. Cada parte gera uma chave pública e usa a chave pública da outra parte para calcular uma chave secreta compartilhada, sem nunca transmitir a chave privada.
  
2. **Cifra de César**: Usada para cifrar e decifrar mensagens com base na chave secreta compartilhada. A cifra de César desloca cada caractere de uma mensagem de acordo com o valor da chave.

## 📂 Arquivos

- **Simple_tcpServer.py**: Implementa o servidor Bob, responsável por receber e decifrar mensagens criptografadas, utilizando a chave gerada via Diffie-Hellman.
- **Simple_tcpClient.py**: Implementa o cliente Alice, responsável por enviar mensagens cifradas utilizando a chave secreta compartilhada via Diffie-Hellman.

## 🚀 Funcionalidades

- **Troca Segura de Chaves**: Geração de chaves pública e privada usando o protocolo Diffie-Hellman.
- **Criptografia de Mensagens**: As mensagens são criptografadas com a Cifra de César, utilizando a chave secreta gerada.
- **Comunicação em Rede**: Comunicação TCP/IP entre um cliente e um servidor em Python.

## ⚙️ Como Executar

### Pré-requisitos

- Python 3.x instalado
- Rede local configurada para permitir comunicação entre servidor e cliente

### Passos

1. Clone o repositório para sua máquina local.
   ```bash
   git clone https://github.com/seu_usuario/seu_repositorio.git
   ```

2. No servidor (Bob), execute o script `Simple_tcpServer.py`.
   ```bash
   python Simple_tcpServer.py
   ```

3. No cliente (Alice), execute o script `Simple_tcpClient.py` e insira a chave privada e a mensagem a ser enviada.
   ```bash
   python Simple_tcpClient.py
   ```

4. O servidor responderá com a mensagem em caixa alta.

## 🛠 Estrutura do Código

### Funções Principais

- **ehPrimo(N)**: Verifica se um número é primo.
- **diffieHellmanR(p, g, chavePrivada)**: Calcula a chave pública (R) usando Diffie-Hellman.
- **diffieHellmanK(p, chavePublica, chavePrivada)**: Calcula a chave secreta compartilhada (K) usando Diffie-Hellman.
- **cifraCesar(modo, mensagem, chave)**: Cifra ou decifra uma mensagem utilizando a Cifra de César.
- **envio(mensagem, p, g, privateSecret, sharedSecretReceived)**: Prepara a mensagem cifrada e a chave pública para envio.
- **recebimento(jsonRecebido, p, privateSecret)**: Decifra a mensagem recebida usando a chave compartilhada.

## 🔐 Segurança

Este projeto é um exemplo didático da implementação de algoritmos de criptografia básicos. Não deve ser usado em ambientes de produção, pois há vulnerabilidades conhecidas na Cifra de César, e os parâmetros usados no Diffie-Hellman são intencionalmente simples.

## 📧 Grupo

- 081200035 - **Abrão Astério Junior**
- 081200034 - **Alexandre Bezerra de Andrade**
- 081200021 - **Daniel Santos de Sousa**
- 081200018 - **Francisco Tommasi Silveira**