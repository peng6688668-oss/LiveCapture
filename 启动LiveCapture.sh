#!/bin/bash
cd /home/localadm/LiveCapture
gnome-terminal -- bash -c 'sudo ./venv/bin/python run.py 2>&1 | tee /tmp/livecapture_output.log; echo "Beendet. Enter drücken..."; read'
