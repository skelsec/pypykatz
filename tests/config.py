import json

TESTFILES_DIR = '/mnt/hgfs/!SHARED/test_dumps/ok'

def compare_jsons(json1, json2):
    """
    Compare two jsons and return True if they are equal, False otherwise
    :param json1: json string
    :param json2: json string
    :return: True if equal, False otherwise
    """
    return json.loads(json1) == json.loads(json2)