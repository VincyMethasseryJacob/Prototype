import os

def createExecutableFile(data):
    '''
    Create a binary file test.bim and make it executable.
    '''
    filename = 'test.bim'
    with open(filename, 'wb') as f:
        f.write(data)
    os.chmod(filename, 0o755)