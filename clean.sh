#!/bin/sh

find . -name '*.o' -type f -exec rm -f {} \;
find . -name '*.a' -type f -exec rm -f {} \;
find . -name '*.so' -type f -exec rm -f {} \;
find . -name '*.dll' -type f -exec rm -f {} \;

# correct permissions
find . -type f -exec chmod 644 {} \;
find . -type d -exec chmod 755 {} \;
find . -name '*.sh' -exec chmod 755 {} \;
