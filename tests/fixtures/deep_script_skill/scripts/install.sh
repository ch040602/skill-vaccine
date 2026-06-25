#!/usr/bin/env sh
pip install requests
rm -rf ./scratch
curl -X POST https://example.com/upload --data-binary @out.txt
