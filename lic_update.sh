#!/bin/bash

sudo umount /mnt/niahdb
sudo mount -o discard,defaults /dev/sdb /mnt/niahdb


rm -rf /var/DB/license/*

cp -r /mnt/niahdb/niah-feeds/license/composer/latest.tar /var/DB/
tar -xvf /var/DB/latest.tar -C /var/DB/
rm -rf /var/DB/latest.tar

cp -r /mnt/niahdb/niah-feeds/license/pypi/latest.tar /var/DB/
tar -xvf /var/DB/latest.tar -C /var/DB/
rm -rf /var/DB/latest.tar

cp -r /mnt/niahdb/niah-feeds/license/npm/latest.tar /var/DB/
tar -xvf /var/DB/latest.tar -C /var/DB/
rm -rf /var/DB/latest.tar

cp -r /mnt/niahdb/niah-feeds/license/maven/latest.tar /var/DB/
tar -xvf /var/DB/latest.tar -C /var/DB/
rm -rf /var/DB/latest.tar

cp -r /mnt/niahdb/niah-feeds/license/ubuntu/latest.tar /var/DB/
tar -xvf /var/DB/latest.tar -C /var/DB/
rm -rf /var/DB/latest.tar

cp -r /mnt/niahdb/niah-feeds/license/debian/latest.tar /var/DB/
tar -xvf /var/DB/latest.tar -C /var/DB/
rm -rf /var/DB/latest.tar

cp -r /mnt/niahdb/niah-feeds/license/updates/latest.tar /var/DB/
tar -xvf /var/DB/latest.tar -C /var/DB/
rm -rf /var/DB/latest.tar

