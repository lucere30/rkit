"""Safe YAML parsing, accelerated by LibYAML when available."""
import yaml

SAFE_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def safe_load(text):
    # Never use Loader/CLoader: upstream payloads are untrusted input.
    return yaml.load(text, Loader=SAFE_LOADER)
