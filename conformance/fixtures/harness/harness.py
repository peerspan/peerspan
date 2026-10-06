"""A launch target that exposes literal arguments and cwd, without a model."""
import json
import os
import sys

print(json.dumps({"arguments": sys.argv[1:], "cwd": os.getcwd()}))
