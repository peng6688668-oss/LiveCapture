#!/bin/bash
cd /home/localadm/LiveCapture
source venv/bin/activate
sudo venv/bin/python run.py 2>&1 | tee /tmp/livecapture_output.log
echo '=== EXIT CODE: $? ==='
echo 'Fertig. Enter druecken...'
read
