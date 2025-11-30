from pyinfra.api.operation import add_op
from pyinfra.operations import server, files
from pyinfra.facts.server import Command
from pyinfra.facts.files import File

import sys

from jinja2 import Environment, FileSystemLoader
import subprocess
import yaml

from omegaconf import OmegaConf as oc
from io import StringIO

def loadSops(secFile, secSopsO):
    try:
        result=subprocess.run(
            ['sops', '--config', secSopsO, '-d', secFile],
            capture_output=True,
            text=True,
            check=True
        )
        decryptedContent=result.stdout
        return decryptedContent
    except FileNotFoundError:
        print(f"WARNING!!!! 'sops' command not found. Is it installed?")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"warning!!!! Could not decrypt sops file {secFile}: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"WARNING!!!! An unexpected error occured with sops file {secFile}: {e}")
        sys.exit(1)

def loadBw(secFile):
    ...

def loadOp(secFile):
    ...

def loadVault(secFile):
    ...

def handleSsh(var):
    ...

def handleTemplating(var):
    ...

SECRET_HANDLERS = {
    'sops': loadSops,
    '1pass': loadOp,
    'bitwarden': loadBw,
    'hashcorp': loadVault,
}

def run_secrets_logic(state, host, choboloPath, skip, secFileO, sopsFileO):
    ChObolo = oc.load(choboloPath)
    secrets = ChObolo.get('secrets')
    secFile = secFileO if secFileO else secrets.get('sec_file')
    sopsFile = sopsFileO if sopsFileO else secrets.get('sec_file')
    templates = secrets.get('templates')

    if secrets and secrets.get('sec_mode') == 'sops' and sopsFile and secFile:
        decryptedContent = loadSops(secFile, sopsFile)
        for t in templates:
            src = t.get('from')
            dest = t.get('to')
            owner = t.get('owner')
            mode = t.get('mode')
