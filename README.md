# Descrição

## Esse repositório contém um script de configuração da base de dados e um script de uma aplicação web flask
## A pasta de templates possui todos os arquivos HTML necessários para renderização assim como
## static possui arquivos CSS de estilização 
 
 - ***finalproject.py*** Script com funcionalidades CRUD da página bem como códigos de autenticação e autorização

-  ***database_setupas.py*** Inicializa a base de dados accessories_store, com 3 tables de armazenamento. 

# Arquivos necessários
 - **finalproject.py**
 
 - **database_setupas.py**

 - **Arquivos de template**

 - **Arquivos static**

 # Instruções de uso e observações

 - O nome da base de dados pode ser modificado a qualquer momento dentro do arquivo database_setupas.py, assim que interpretado, todas as funcionalidades da página estarão disponíveis

  - *Cada table em database_setupas.py possui um método serialize para representação JSON

   - A versão final do servidor desse projeto foi inicializada na porta 5050, em uma virtual machine, para fins de compatibilidade com outros processos, sinta-se a vontade para fazer a modificação

# Bibliotecas e frameworks
- **Flask**
- **SQLALchemy**
- **JSON**
- **oauth2**
- **httplib2**
- **requests**
