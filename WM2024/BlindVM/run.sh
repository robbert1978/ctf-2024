docker rm -f blindvm
docker build -t blindvm:latest .
docker run -it -d --name blindvm -p 9999:9999 blindvm:latest