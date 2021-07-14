# Versão em português
## Protótipo de validação
Este repositório traz o protótipo FWunify, desenvolvido como forma de validação para a linguagem FWlang, utilizada no gerenciamento de firewalls em redes híbridas (redes compostas de equipamentos tradicionais e SDN).

## Instalação do software
ATENÇÃO: Esse processo de instação/utilização foi testado e validado para Ubuntu 20.04. Instalações em outras distribuições podem necessitar ajustes.

Faça a instalação do GIT e do virtualenv:

`sudo apt-get install git virtualenv`
* Será solicitada a senha do usuário

Utilize os comandos abaixo para criar e ativar a virtualenv do projeto:

```bash
virtualenv venv_firewall --python=python3
source venv_firewall/bin/activate
cd venv_firewall
```

Faça o download do projeto utilizando git

`git clone https://github.com/mmfiorenza/fwunify`

Acesse a pasta do projeto.

`cd fwunify`

Execute o script "preparing_environment.sh" para instalação das dependências

`bash scripts/setup.sh`

* Poderá ser solicitada a senha de usuário para instalação dos pacotes

## Preparação da máquina
Para aplicar as regras traduzidas no firewall IPTables do sistema operacional, será necessário configurar o acesso ssh, bem como a criação de um usuário para este fim. 

Faça a instalação do servidor SSH:

`sudo apt-get install openssh-server`

Crie o usuário admin:

`sudo useradd admin ; sudo passwd admin`
* Quando solicitada a senha, digite "admin", sem aspas.

Execute o comando abaixo para ajustar as permissões:

`usermod -G sudo admin`

## Uso
Certifique-se que esteja na virtualenv criada para o projeto, indicada por "(venv_firewall)" no console.
Caso não esteja, execute o comando abaixo:

`source ../bin/activate`

Execute os módulos tradutores utilizando o script “run_application.sh”

`bash scripts/start_microservices.sh`

Execute a API para recepção das intenções

`python src/api.py`

Em outro terminal, utilize o método HTTP POST (por exemplo: comando curl) para enviar a intenção em FWlang para a aplicação:

```bash
curl -u user1:user1 --data-binary "@intent.txt" -X POST http://localhost:5000
```
Exemplos das três intenções suportadas estão disponíveis na pasta “intent_examples”.


## Suporte
Este software não possui nenhuma forma de suporte. Caso tenha alguma dúvida favor enviar um e-mail para mauriciofiorenza.aluno@unipampa.edu.br.


## Creditos
* Desenvolvimento: Maurício Fiorenza
* Orientação: Diego Kreutz