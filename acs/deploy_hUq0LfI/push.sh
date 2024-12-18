#!/bin/sh

docker login -u TEAM7 -p adWEKHnz9mDwa1z! https://registry.acstestapp.net/harbor/projects/8/repositories/
docker build . -t vote:patched
docker tag vote:patched registry.acstestapp.net/team7/vote-vote:latest
docker push registry.acstestapp.net/team7/vote-vote:latest
