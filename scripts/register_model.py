#!/usr/bin/env python
import argparse
from mlops import ModelRegistry
p=argparse.ArgumentParser(); p.add_argument("version"); p.add_argument("--metrics",default="{}"); p.add_argument("--metadata",default="{}")
a=p.parse_args(); import json
r=ModelRegistry(); print(json.dumps(r.register(a.version,json.loads(a.metrics),json.loads(a.metadata)),indent=2))
