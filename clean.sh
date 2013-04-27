#!/bin/sh

rm -f *.o
rm -f *.a
rm -f *.so
rm -f *.so.*

# correct permissions
find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;
find *.sh -exec chmod +x {} \;
