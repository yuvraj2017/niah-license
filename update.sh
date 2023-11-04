#!/bin/bash


sudo umount /mnt/niahdb
sudo mount -o discard,defaults /dev/sdb /mnt/niahdb

rm -rf /var/DB/feeds/*

tar -xvf /mnt/niahdb/niah-feeds/vuln/latest.tar -C /tmp/

mv /tmp/feeds/cves /var/DB/feeds/
mv /tmp/feeds/cvedb /var/DB/feeds/
mv /tmp/feeds/browse /var/DB/feeds/
mv /tmp/feeds/language /var/DB/feeds/
mv /tmp/feeds/platform /var/DB/feeds/
mv /tmp/feeds/updates /var/DB/feeds/

rm -rf /tmp/feeds

tar -xvf /mnt/niahdb/niah-feeds/license/latest.tar -C /tmp/
mv /tmp/license/* /var/DB/license/

