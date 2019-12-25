import logging
from typing import List

from volatility.framework import interfaces, constants, exceptions, symbols
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.framework.layers.scanners import MultiStringScanner
from volatility.plugins.windows import pslist, vadinfo