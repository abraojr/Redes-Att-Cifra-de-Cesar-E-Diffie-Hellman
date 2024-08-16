# Cifra de César com Chave Gerada usando Diffie-Hellman

O projeto implementa uma comunicação segura utilizando a Cifra de César com uma chave gerada dinamicamente usando o algoritmo de troca de chaves Diffie-Hellman. O código permite a troca de mensagens criptografadas entre dois participantes através de uma conexão TCP.

## Arquivos

- **Simple_tcpServer.py**: Implementa um servidor TCP que aguarda conexões de clientes.
- **Simple_tcpClient.py**: Implementa um cliente TCP que se conecta ao servidor e envia uma mensagem.

## Pré-requisitos

- Python 3.x instalado no sistema.

## Como executar

### Executando o servidor

1. Primeiro, inicie o servidor TCP. Abra um terminal e execute o seguinte comando:

   ```bash
   python3 Simple_tcpServer.py
   ```

O servidor será iniciado e ficará aguardando por conexões na porta especificada.

### Executando o cliente

2. Em seguida, em outro terminal, execute o cliente TCP:

   ```bash
   python3 Simple_tcpClient.py
   ```

   O cliente tentará se conectar ao servidor e enviar uma mensagem predefinida.

## Funcionalidades

- **Verificação de número primo**: Verifica se um número dado é primo, essencial para o algoritmo de Diffie-Hellman.
- **Geração de chave Diffie-Hellman**: Gera chaves públicas e privadas usando os parâmetros compartilhados e segredos privados.
- **Cifra de César**: Implementa a cifra de César para criptografar e descriptografar mensagens usando a chave gerada.
- **Envio de mensagens**: Criptografa e envia uma mensagem usando a chave privada e pública.
- **Recebimento de mensagens**: Recebe e descriptografa uma mensagem usando a chave privada e a chave pública recebida.

## Estrutura do Código

1. **Função `ehPrimo(N)`**: Verifica se um número `N` é primo.
2. **Função `diffie_hellman(p, g, chavePrivada)`**: Calcula a chave pública usando os parâmetros `p` (número primo), `g` (base) e uma `chavePrivada`.
3. **Função `cifraCesar(modo, mensagem, chave)`**: Aplica a Cifra de César para criptografar (`modo = 'E'`) ou descriptografar (`modo = 'D'`) uma mensagem usando a `chave`.
4. **Função `envio(mensagem, p, g, privateSecret)`**: Criptografa a mensagem e envia juntamente com a chave pública.
5. **Função `recebimento(mensagem, p, sharedSecretReceived, privateSecret)`**: Descriptografa a mensagem recebida usando a chave pública recebida e a chave privada.

## Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
