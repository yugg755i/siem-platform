from datetime import datetime
import random

USERS = ["john", "root", "admin"]
IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.50"]
ATTACKER_IPS = [
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
    "198.51.100.10",
    "198.51.100.11",
    "192.0.2.10",
    "192.0.2.11",
]

with open("logs/auth.log", "w") as file:

    for _ in range(500):

        user = random.choice(USERS)
        ip = random.choice(IPS)

        line = (
            f"{datetime.now().strftime("%b %d %H:%M:%S")} ubuntu sshd[1234]: "
            f"Accepted password for {user} "
            f"from {ip} port 22 ssh2\n"
        )
        file.write(line)

    for _ in range(200):

        ip = random.choice(ATTACKER_IPS)

        line = (
            f"{datetime.now().strftime("%b %d %H:%M:%S")} ubuntu sshd[1234]: "
            f"Failed password for invalid user admin "
            f"from {ip} port 22 ssh2\n"
        )
        file.write(line)


