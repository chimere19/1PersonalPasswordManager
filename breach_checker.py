import hashlib
import requests

def check_password_breach(password):
    sha1_pwd = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_pwd[:5]
    suffix = sha1_pwd[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return -1

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)

    return 0
