import json
from langchain_core.messages import BaseMessage, message_to_dict
import os
import time
from datetime import datetime
import logging
import sys
from typing import Optional

# Per-node logging for a running analysis

def log_local(log_dir: str, node: str, step_count: int, message: BaseMessage):
    log_path = os.path.join(log_dir, f"step_{step_count}_{node}.json")
    message_dict = message_to_dict(message)
    # Add a timestamp
    timestamp = time.time()
    message_dict["timestamp"] = timestamp
    message_dict["time"] = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(message_dict, f, ensure_ascii=False, indent=2)

# Lower-level JSON log helper
def log_json(log_dir: str, json_name: str, content: dict):
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{json_name}.json")
    timestamp = time.time()
    content["timestamp"] = timestamp
    content["time"] = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(content, f, ensure_ascii=False, indent=2)


def log_message(log_dir: str, file_name:str, message: BaseMessage):
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, file_name)
    message_dict = message_to_dict(message)
    # Add a timestamp
    timestamp = time.time()
    message_dict["timestamp"] = timestamp
    message_dict["time"] = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(message_dict, f, ensure_ascii=False, indent=2)

# Stdout logging helper
class StdoutLogger:

    @classmethod
    def stdout_log(cls, message: str, logtype="info", phase=""):
        message = str(message)
        if len(phase) > 0:
            phase = f" [{phase}]"
        t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        s = f"[{logtype.upper()}] [{t}]{phase} {message}"
        print(s)

    @classmethod
    def info(cls, message: str, phase=""):
        cls.stdout_log(message, "info", phase)  

    @classmethod
    def debug(cls, message: str, phase=""):
        cls.stdout_log(message, "debug", phase) 

    @classmethod
    def warning(cls, message: str, phase=""):
        cls.stdout_log(message, "warning", phase) 

    @classmethod
    def error(cls, message: str, phase=""):
        cls.stdout_log(message, "error", phase) 

    @staticmethod
    def print(message: str, end=None):
        print(message, end=end)