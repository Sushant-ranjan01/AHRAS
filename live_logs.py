LOG_FILE = "logs/security_logs.txt"


def add_log(message):

    try:

        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(message + "\n")

    except Exception as e:

        print("Log Write Error:", e)


def get_logs():

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            lines = file.readlines()

        lines = [line.strip() for line in lines]

        return lines[-100:]

    except:

        return []