
This repository brings the FWUnify prototype, developed for managing multiple firewalls in corporate networks.

## Usage

## Manual installation and usage

First, make sure you have the following requirements:

- [Python](https://www.python.org/) >= 3.8.10
- [pipnev](https://pypi.org/project/pipenv/) >= 2022.5.2
- iptables
- ssh
- [RabbitMQ](https://www.rabbitmq.com/download.html) == 3.10.7

Then, start by using **pipenv** to install all dependencies:

```bash
pipenv install -d
```

**WARNING:** *Ensure that the SSH service is enabled and that the settings in /etc/ssh/sshd_config do allow for text password access*

Create an user to be used by FWUnify:

```bash
sudo useradd -G sudo -p fwunify fwunify
```

Access the virtual environment

```bash
pipenv shell
```

Make sure **RabbitMQ** services are enabled and working:

```bash
sudo rabbitmq-plugins enable rabbitmq_management
sudo service rabbitmq-server restart
```

If everything is setup and working, then it's time to start the micro-services required for FWUnify to work:

`bash scripts/start_microservices.sh`

Lastly, run FWUnify with:

`python src/api.py`

## Credits
Development: Maurício Fiorenza
Orientation: Diego Kreutz
