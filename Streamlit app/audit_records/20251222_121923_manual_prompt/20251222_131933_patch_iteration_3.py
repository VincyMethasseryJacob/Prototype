import json
import pickle
import base64

def deserialize_base64_pickle(b64_string):
    data = base64.b64decode(b64_string)
    obj = json.loads(data)
    return obj