import os
import logging
import json
from logging.handlers import TimedRotatingFileHandler

def get_log_config(package_name: str) -> dict:
    root_dir = os.path.abspath(os.curdir)
    config_path = os.path.join(root_dir, 'config/log_config.json')
    if not os.path.isfile(config_path):
        config_path = os.path.join(root_dir, '../config/log_config.json')
    with open(config_path, 'r') as file:
        config = json.load(file)
    return config[package_name]


def get_log_level_from_config(config: dict) -> int:
    if config['log_level'] == 'debug':
        return logging.DEBUG
    elif config['log_level'] == 'info':
        return logging.INFO
    elif config['log_level'] == 'error':
        return logging.ERROR


def init_logging(module_name: str,
                 package_name: str) -> logging:
    dict_cfg = get_log_config(package_name)
    logger = logging.getLogger(module_name)
    root_dir = os.path.abspath(os.curdir)
    log_dir = os.path.join(root_dir, 'logs')
    if not os.path.isdir(log_dir):
        log_dir = os.path.join(root_dir, '../logs')
    file_handler = TimedRotatingFileHandler(
        filename=os.path.join(log_dir, dict_cfg['file_name']),
        when='midnight',
        interval=1,
        backupCount=dict_cfg['backup_days'],
        encoding='utf-8',
        delay=False
    )
    formatter = logging.Formatter(fmt='[%(asctime)s] [%(levelname)s] - %(name)s - Func:%(funcName)s - Line:%(lineno)d - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.setLevel(get_log_level_from_config(dict_cfg))
    return logger
