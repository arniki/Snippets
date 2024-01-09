## Infrastructure Overview

Our infrastructure is divided into 5 main parts: web, app, database, DNS and monitoring services.
The running services are as follows:

- Web services - Nginx
- App services - Agama
- Database services - MySQL, InfluxDB
- DNS service - Bind9
- Monitoring services - Prometheus, Grafana, Telegraf
- Ansible repository - https://github.com/arniki/ica0002

This document contains the information about:

- Backup coverage -- what is backed up and what is not
- Backup RPO (recovery point objective)
  Versioning and retention -- how many backup versions are stored and for how long
- Usability -- how is backup recovery verified
- Restoration criteria -- when should backup be restored
- Backup RTO (recovery time objective)

# Backup coverage

Backed up services include:

- MySQL
- Grafana

Web services, App services and DNS services are important, however they do not contain or produce any sensitive/valuable data. All important information is stored in our databases (MySQL and InfluxDB), therefore backing them up instead is essential.

Grafana is a data visualization tool, and in our infrastructure works in conjunction with Prometheus and InfluxDB. Setting up Grafana manually is time-consuming and it cannot be restored by any other means. Therefore it also needs backing up.

# Backup RPO

Recovery point objectives refer to loss tolerance: the amount of data that can be lost before significant harm to the business occurs. The objective is expressed as a time measurement from the loss event to the most recent preceding backup.

# Recovery points to be edited for prod

Recovery point objective for backed up services:

- MySQL - 28 days.
- InfluxDB - 28 days.
- Grafana - 7 days.

Due to almost weekly changes to our Grafana configuration, RPO is short. Since our provided service doesn't really have any importance behind it as of now, there is no need to have a shorter RPO for our Databases. In the future, when the userbase and provided value grows, backup RPO is subject to change.

# Versioning and retention

- MySQL backups are retained for 56 days. 2 versions can be stored at the same time.

- Grafana backups are retained for 14 days. 2 versions should be stored at the same time.

# Usability

Usability of the last MySQL and Grafana backup is checked every week in a test environment, that simulates our real infrastructure.

# Restoration criteria

Services should be restored only, if it was detected, that data was altered, corrupted or deleted by unauthorized people

OR

If the service stopped working, and no troubleshooting can fix it.

# Backup RTO

Backup recovery should take <2 hours.
