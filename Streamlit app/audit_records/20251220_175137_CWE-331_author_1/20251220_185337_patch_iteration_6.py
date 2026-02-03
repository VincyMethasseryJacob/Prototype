def generateRandomString(length):
    return ''.join(random.choices(string.ascii_letters, k=length))