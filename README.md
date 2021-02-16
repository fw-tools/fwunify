# Versão em português
## Protótipo de validação
Este repositório traz o protótipo FWunify, desenvolvido como forma de validação para a linguagem FWlang, utilizada no gerenciamento de firewalls em redes híbridas (redes compostas de equipamentos tradicionais e SDN).

## Instalação do software
ATENÇÃO: Esse processo de instação/utilização foi testado e validado para Ubuntu 18.04. Instalações em outras distribuições podem necessitar ajustes.

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


## Uso
Certifique-se que esteja na virtualenv criada para o projeto, indicada por "(venv_firewall)" no console.
Caso não esteja, execute o comando abaixo:

`source ../bin/activate`

Execute os módulos tradutores utilizando o script “run_application.sh”

`bash scripts/start_microservices.sh`

Execute a API para recepção das intenções

`python src/api.py`

Em outro terminal, utilize o método HTTP POST (por exemplo: comando curl) para enviar a intenção em NILE para a aplicação:

```bash
curl -u user1:user1 --data-binary "@intent.txt" -X POST http://localhost:5000
```
Exemplos das três intenções suportadas estão disponíveis na pasta “intent_examples”.


## Suporte
Este software não possui nenhuma forma de suporte. Caso tenha alguma dúvida favor enviar um e-mail para mauriciofiorenza.aluno@unipampa.edu.br.


## Creditos
* Desenvolvimento: Maurício Fiorenza
* Orientação: Diego Kreutz



# English version
## Validation prototype
This repository presents the FWunify prototype, developed as a form of validation for the FWlang language, used in firewall management in hybrid networks  (networks composed of traditional equipment and SDN).

## Software installation
ATTENTION: This installation/use process has been tested and validated for Ubuntu 18.04. Installations in other distributions may require adjustments.

Install GIT and virtualenv:

`sudo apt-get install git virtualenv`
* User password will be requested

Use the commands below to create and activate the project's virtualenv:

```bash
virtualenv venv_firewall --python=python3
source venv_firewall/bin/activate
cd venv_firewall
```

Download the project using git

`git clone https://github.com/mmfiorenza/fwunify`

Access the project folder.

`cd fwunify`

Run the "preparing_environment.sh" script to install the dependenciess

`bash scripts/setup.sh`


## Usage
Make sure you are in the virtualenv created for the project, indicated by "(venv_firewall)" in the console.
If not, run the command below:

`source ../bin/activate`

Run the translator modules using the script “run_application.sh”

```bash
bash scripts/start_microservices.sh
```

Run the API to receive intentions

```bash
python src/api.py
```

In another terminal, use the HTTP POST method (for example: curl command) to send the intention in NILE to the application:

```bash
curl --data-binary "@intent.txt" -X POST http://localhost:5000
```
Examples of the three supported intentions are available in the “intent_examples” folder.


## Support
This software does not have any form of support. If you have any questions please send an email to mauriciofiorenza.aluno@unipampa.edu.br.


## Credits
* Development: Maurício Fiorenza
* Mentor: Diego Kreutz
