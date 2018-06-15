#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import os
import re
import struct
import logging
import traceback
import json
import ntpath


from pypykatz.pypykatz import pypykatz
from pypykatz.commons.common import UniversalEncoder

if __name__ == '__main__':
	logging.basicConfig(level=1)
	mimi = pypykatz.go_live()
	
	print(json.dumps(mimi, cls = UniversalEncoder, indent=4, sort_keys=True))
