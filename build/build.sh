#!/bin/bash

echo "building started"

COMMIT=`git log --format="%H" -n 1`
DATE=$(date '+%Y-%m-%d')

BUILD_NAME=niah-license-$COMMIT-$DATE.deb


BUILD_DIR=niah-license-$1

echo $BUILD_DIR

mkdir $BUILD_DIR

mkdir $BUILD_DIR/usr/
mkdir $BUILD_DIR/usr/share
mkdir $BUILD_DIR/usr/share/niah-license/
mkdir $BUILD_DIR/usr/share/niah-license/src

echo "package building started"

cp -r build/DEBIAN $BUILD_DIR/
cp install/niah-install $BUILD_DIR/usr/share/niah-license/
cp install/niah-remove $BUILD_DIR/usr/share/niah-license/
cp config.cfg $BUILD_DIR/usr/share/niah-license/
cp install/nginx.conf $BUILD_DIR/usr/share/niah-license/
cp service/niah-license.service $BUILD_DIR/usr/share/niah-license/
cp install/pg_hba.conf $BUILD_DIR/usr/share/niah-license/
cp install/requirements.txt $BUILD_DIR/usr/share/niah-license/
cp install/niah-license $BUILD_DIR/usr/share/niah-license/
cp install/s.dump $BUILD_DIR/usr/share/niah-license/

cp README.md $BUILD_DIR/usr/share/niah-license/src
cp README.txt $BUILD_DIR/usr/share/niah-license/src
cp application.config $BUILD_DIR/usr/share/niah-license/src
cp config.cfg $BUILD_DIR/usr/share/niah-license/src
cp credit_code_map.json $BUILD_DIR/usr/share/niah-license/src
cp deb_test.py $BUILD_DIR/usr/share/niah-license/src
cp eco.json $BUILD_DIR/usr/share/niah-license/src
cp lic_update.sh $BUILD_DIR/usr/share/niah-license/src
cp license_test.py $BUILD_DIR/usr/share/niah-license/src
cp mail_api.py $BUILD_DIR/usr/share/niah-license/src
cp p.py $BUILD_DIR/usr/share/niah-license/src
cp passive_api.py $BUILD_DIR/usr/share/niah-license/src
cp post_update.py $BUILD_DIR/usr/share/niah-license/src
cp sub_details.json $BUILD_DIR/usr/share/niah-license/src
cp test_lic.py $BUILD_DIR/usr/share/niah-license/src
cp update.sh $BUILD_DIR/usr/share/niah-license/src
cp yash.py $BUILD_DIR/usr/share/niah-license/src
cp -r celery $BUILD_DIR/usr/share/niah-license/src
cp connectors.py $BUILD_DIR/usr/share/niah-license/src
cp file.py $BUILD_DIR/usr/share/niah-license/src
cp generate_report.py $BUILD_DIR/usr/share/niah-license/src
cp getFeed.py $BUILD_DIR/usr/share/niah-license/src
cp -r lib $BUILD_DIR/usr/share/niah-license/src
cp plugin.config $BUILD_DIR/usr/share/niah-license/src
cp -r service $BUILD_DIR/usr/share/niah-license/src
cp -r static $BUILD_DIR/usr/share/niah-license/src
cp web.py $BUILD_DIR/usr/share/niah-license/src
cp webUi_uwsgi.ini $BUILD_DIR/usr/share/niah-license/src
cp wsgi.py $BUILD_DIR/usr/share/niah-license/src
cp startup/celeryd.service $BUILD_DIR/usr/share/niah-license
cp startup/celeryd $BUILD_DIR/usr/share/niah-license
cp startup/rc.local $BUILD_DIR/usr/share/niah-license

echo "package building completed"

echo "started deb package creation"
dpkg-deb --build $BUILD_DIR $BUILD_NAME

mkdir /var/niah/build/niah-license/$1/$DATE

cp $BUILD_NAME /var/niah/build/niah-license/$1/$DATE

