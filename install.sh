#!/bin/sh

cp -r include/kripto /usr/include/kripto
cp lib/libkripto.a /usr/lib
cp lib/libkripto.so /usr/lib

chown -R root:root /usr/include/kripto
chown root:root /usr/lib/libkripto.a
chown root:root /usr/lib/libkripto.so

chmod -R 644 /usr/include/kripto
find /usr/include/kripto -type d -exec chmod 0755 {} \;
chmod 644 /usr/lib/libkripto.a
chmod 755 /usr/lib/libkripto.so
