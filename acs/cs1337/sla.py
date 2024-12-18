import requests

PATCHED = 0
ONLINE = 1
OFFLINE = 2


def test_case1(ip):
    try:
        req = requests.post(f'http://{ip}:1338/signup',
                            data={'id': 'zzlol123', 'pw': 'zzlol123'})

        if req.status_code == 200:
            return ONLINE
        elif req.status_code == 409:
            return ONLINE
        else:
            return OFFLINE
    except requests.exceptions.RequestException:
        return OFFLINE


def test_case2(ip):
    try:
        req = requests.post(f'http://{ip}:1338/login',
                            data={'id': 'zzlol', 'pw': 'zzlol'})

        if req.status_code == 200:
            return ONLINE
        else:
            return OFFLINE
    except requests.exceptions.RequestException:
        return OFFLINE


def test_case3(ip):
    try:
        fd_url = f'http://{ip}:1338//proc/self/fdinfo/'
        real_fd = -1
        for i in range(100):
            req = requests.get(fd_url + str(i), cookies={'id': 'zzlol'})
            fd = req.text
            if 'File not found' in fd:
                real_fd = i

        if real_fd == -1:
            return PATCHED
        else:
            return ONLINE
    except requests.exceptions.RequestException:
        return OFFLINE


def check_status(ip):
    try:
        if test_case1(ip) == OFFLINE:
            return OFFLINE

        print('check 1 pass')

        if test_case2(ip) == OFFLINE:
            return OFFLINE

        print('check 2 pass')

        if test_case3(ip) == PATCHED:
            print('patched')
            return PATCHED

        if test_case3(ip) == OFFLINE:
            return OFFLINE

        print('check 3 pass')
        return ONLINE

    except Exception:  # Catch any other unexpected errors
        return OFFLINE


if __name__ == '__main__':
    # Example usage with localhost
    print(check_status('localhost'))
