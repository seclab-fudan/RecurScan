import logging.config
import os
import warnings

import ruamel.yaml

warnings.filterwarnings("ignore")

from config.consts import *
from config.path import *

___logging_config_file = os.path.join(CONFIG_PATH, 'logging.yaml')

yaml = ruamel.yaml.YAML()
logfile = os.path.join(LOG_PATH, 'rcs.log')

with open(___logging_config_file, 'r', encoding='utf-8') as f:
    logging.config.dictConfig(yaml.load(f))

import coloredlogs

coloredlogs.install()
