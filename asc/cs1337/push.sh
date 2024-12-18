#!/bin/sh
# Login
docker login -u TEAM7 -p adWEKHnz9mDwa1z! https://registry.acstestapp.net/harbor/projects/8/repositories/

# Build local patch
docker build . -t cs1337:patched

# Tag image
docker tag cs1337:patched registry.acstestapp.net/team7/cs1337-cs1337:latest

# Push image
docker push registry.acstestapp.net/team7/cs1337-cs1337
