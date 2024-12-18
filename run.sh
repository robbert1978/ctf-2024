#!/bin/sh

socat tcp-listen:9000,fork,reuseaddr exec:./server &
socat tcp-listen:9001,fork,reuseaddr exec:./client &
while true; do sleep 1; done