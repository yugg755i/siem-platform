from datetime import datetime
import random

NORMAL_PATHS = [
    "/",
    "/login",
    "/about",
    "/contact",
    "/dashboard"
]

SCAN_PATHS = [
    "/admin",
    "/phpmyadmin",
    "/wp-admin",
    "/.env",
    "/config.php",
    "/backup.zip"
]

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30"
]

ATTACKER_IP = "203.0.113.50"

def apache_generator():
    with open("logs/apache.log", "w") as file:

        for _ in range(400):

            path = random.choice(NORMAL_PATHS)
            ip = random.choice(NORMAL_IPS)

            line = (
                f'{ip} - - '
                f'[{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
                f'"GET {path} HTTP/1.1" 200 1234\n'
            )
            file.write(line)

        for _ in range(100):

            path = random.choice(SCAN_PATHS)
    
            line = (
                f'{ATTACKER_IP} - - '
                f'[{datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
                f'"GET {path} HTTP/1.1" 404 512\n'
            )
            file.write(line)

