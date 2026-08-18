import base64
import pathlib
p = pathlib.Path('trusted_devices.json')
print(base64.b64encode(p.read_bytes()).decode('ascii'))
