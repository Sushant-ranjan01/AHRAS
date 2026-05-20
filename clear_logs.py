def clear_logs():

    try:

        with open(
            "logs/security_logs.txt",
            "w"
        ) as f:

            f.write("")

        print(
            "Security logs cleared successfully."
        )

    except Exception as e:

        print(
            "Error clearing logs:",
            e
        )


if __name__ == "__main__":

    clear_logs()