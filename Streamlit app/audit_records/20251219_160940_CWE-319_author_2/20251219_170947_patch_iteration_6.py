def downloadFile(hostname, username, password, sensitive_file):
    with ftplib.FTP(hostname) as ftp:
        ftp.login(user=username, passwd=password)
        with open(os.path.basename(sensitive_file), 'wb') as f:
            ftp.retrbinary(f"RETR {sensitive_file}", f.write)