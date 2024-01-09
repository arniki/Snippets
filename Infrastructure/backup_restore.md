# Restoration of services

In case any of the services are down.
(for verification you can use command "service <service name> status". E.G "service nginx status)
Run the commands below on the main machine, with ansible installed, from the directory where ansible is installed. Make sure your "hosts" file is up-to-date.

## Users Roman and Juri

ansible-playbook lab02_web_server.yaml


## Nginx

ansible-playbook lab02_web_server.yaml


## Agama

ansible-playbook lab04_web_app.yaml


## MySQL

ansible-playbook ansible-playbook lab04_web_app.yaml  
ansible-playbook ansible-playbook lab07_grafana.yaml  
ansible-playbook ansible-playbook lab10_backups.yaml  


## UWSGI

ansible-playbook lab04_web_app.yaml


## DNS (Bind9 + configuration)

ansible-playbook lab05_dns.yaml


## Prometheus

ansible-playbook lab06_prometheus.yaml


## Node exporters (theres 2)

ansible-playbook lab06_prometheus.yaml


## Bind9 exporter

ansible-playbook lab07_grafana.yaml


## MySQL exporter

ansible-playbook lab07_grafana.yaml


## Nginx exporters (there's one on both machines)

ansible-playbook lab07_grafana.yaml

## Grafana

ansible-playbook ansible-playbook lab07_grafana.yaml


## InfluxDB

ansible-playbook lab08_logging.yaml


## Pinger

ansible-playbook lab08_logging.yaml


## Backup system (cron + duplicity)

ansible-playbook lab10_backups.yaml


## Rsyslog

ansible-playbook lab08_logging.yaml


## Telegraf

ansible-playbook lab08_logging.yaml


# Restoration of backups

## Restore MySQL databaseConnect to the machine, that has mysql installed.
Become root with "sudo -i"

1)
duplicity --no-encryption restore rsync://arniki@backup.cool.af//home/arniki /home/backup/restore/

2)
mysql agama < /home/backup/restore/agama.sql

To verify the successful backup restoration, refresh agama webpage.



## Restore Grafana
Become sudo with sudo -i

1)
duplicity --no-encryption --force restore rsync://arniki@backup.cool.af//home/arniki /home/backup/restore/
2)
docker stop grafana
3)
rsync -a --delete /home/backup/backup/grafana.docker.etc/grafana-etc/ /opt/docker/grafana-etc/
4)
rsync -a --delete home/backup/backup/grafana.docker.lib/grafana/ /opt/docker/grafana/
5)
chown -R 472:472 /opt/docker/grafana-etc
6)
chown -R 472:472 /opt/docker/grafana
7)
docker start grafana


