def ingest_log(path):
    with open(path) as file:
        return file.readlines()

