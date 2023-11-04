#1/bin/bash

sudo rm -rf env

# Install apt-get
sudo apt-get update
sudo apt-get install python3-pip -y
sudo apt-get install python3-venv -y
sudo apt-get install nginx
sudo cp install/nginx.conf /etc/nginx/nginx.conf
sudo service nginx restart
sudo apt install postgresql postgresql-contrib -y
sudo /etc/postgresql/10/main/pg_hba.conf /etc/postgresql/10/main/pg_hba.conf.org
sudo cp install/pg_hba.conf /etc/postgresql/10/main/pg_hba.conf
sudo service postgresql restart

sudo -u postgres psql -c "CREATE DATABASE niahdb;"
sudo -u postgres psql -c "CREATE USER versa WITH ENCRYPTED PASSWORD 'versa123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE niahdb TO versa;"

# Virtual ENV
sudo pip3 install virtualenv
python3 -m venv env

# Connect VENV and Install requirements.txt
source env/bin/activate
python3 -m pip install --upgrade pip
pip3 install -r install/requirements.txt
deactivate

# Dump DB Schema
set PGPASSWORD=versa123&&psql niahdb versa < install/s.dump

# Notification Table
export PGPASSWORD='versa123'&&psql niahdb versa -c "insert into notification_db(notification_id, notification_name, notification_email, notification_textmessage, notification_phonecall) values(2, 'onlyEmail', 'yes', 'no', 'no');"
export PGPASSWORD='versa123'&&psql niahdb versa -c "insert into notification_db(notification_id, notification_name, notification_email, notification_textmessage, notification_phonecall) values(1, 'AlertAll', 'yes', 'no', 'yes');"

# Subscription Table
export PGPASSWORD='versa123'&&psql niahdb versa -c "insert into subscription_db(id, subscription_name, scans, users, modules, description) values ('1', 'NiahLite', 3, 10, 'dependencies', 'Only for developers');"
export PGPASSWORD='versa123'&&psql niahdb versa -c "insert into subscription_db(id, subscription_name, scans, users, modules, description) values ('2', 'NiahEnterprise', 10, 10, 'dependencies,applications,vulnalerts,reporting,platforms', 'Only for Enterprise');"
export PGPASSWORD='versa123'&&psql niahdb versa -c "insert into subscription_db(id, subscription_name, scans, users, modules, description) values ('3', 'NiahFlexi', 0, 0, 'dependencies,applications,vulnalerts,reporting,platforms', 'Custom Users');"
export PGPASSWORD='versa123'&&psql niahdb versa -c "insert into subscription_db(id, subscription_name, scans, users, modules, description) values ('4',  'Free', 100, 1, 'dependencies,applications,vulnalerts,reporting,platforms', 'Free User');"


# set services
sudo cp service/niahapi.service /etc/systemd/system/niahapi.service
sudo systemctl daemon-reload

