import random
import json
from datetime import datetime

EVENTS = [4624, 4625, 4720, 4726, 4732]

USERS = ["john", "eviladmin", "cat", "ramesh", "administrator"]

IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.50"]

def windows_generator():
    with open("logs/windows.log", "w") as file:

        for _ in range(500):

            line = {
                "@timestamp": datetime.now().isoformat(),
                "winlog": {
                    "event_id": random.choice(EVENTS),
                    "event_data": {
                        "TargetUserName": random.choice(USERS),
                        "IpAddress": random.choice(IPS)
                        }
                    }
                }

            file.write(json.dumps(line) + "\n")

