import yaml
from IgnoreLoader import IgnoreLoader
import json

if __name__ == "__main__":
    with open("test.yaml", "r") as f:
        data = yaml.load(f, IgnoreLoader)
        print(json.dumps(data, indent=2))
