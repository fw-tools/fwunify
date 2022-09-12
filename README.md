[//]: # (Add FWUnify banner here)
This repository hosts the FWUnify prototype, developed for managing multiple firewalls in corporate networks.

## Usage

To use this application, simply create and run a Docker container using the image available [here](https://github.com/fw-tools/fwunify/pkgs/container/fwunify).

Or, if you wish, you can also build the image yourself with the provided `Dockerfile`.

You can find some examples of firewall rules at `intent_example`, use `curl` to send those rules to your running FWUnify environment:

```bash
cd intent_examples
curl -u user1:user1 --data-binary "@intent_acl_1.txt" -X POST http://localhost:5000
```

Now you can verify the firewall rules, such as with `iptables`:

```bash
sudo iptables -L
```

To remove a rule, edit it replacing the "add" marker with "del" and send the intent again with `curl`, or if you prefer, run the command below:

```bash
sudo iptables -F
```

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

```bash
bash scripts/start_microservices.sh
```

Lastly, run FWUnify with:

```bash
python src/api.py
```

## Credits
Development: Maurício Fiorenza

Guidance: Diego Kreutz
