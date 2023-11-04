Installation Guide : https://www.linode.com/docs/guides/task-queue-celery-rabbitmq/

cp /etc/systemd/system/celeryd.service
cp /etc/default/celeryd
sudo mkdir /var/log/celery /var/run/celery
sudo chown celery:celery /var/log/celery /var/run/celery
sudo systemctl daemon-reload
sudo systemctl enable celeryd
sudo systemctl start celeryd

