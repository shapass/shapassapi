#!/bin/bash

# This script needs a .pgpass file in the /home/postgres
# directory in the format. (https://www.postgresql.org/docs/current/libpq-pgpass.html)
# and needs to be run as the postgres user
#
# hostname:port:database:username:password

# recommended crontab
# 0 0 * * * /usr/local/backup_shapass.sh

DATE_NOW=$(date +%Y-%m-%d)
pg_dump -h localhost shapassapi > /tmp/shapass_dump_${DATE_NOW}.sql
