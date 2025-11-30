import os
from pyinfra.api.operation import add_op
from pyinfra.operations import server, files
from pyinfra.facts.server import Command
from pyinfra.facts.files import File

import sys

from jinja2 import Environment, FileSystemLoader
import subprocess

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

def handleTemplating(
    state,
    host,
    vars: list[str],
    src: str,
    dest: str,
    owner: str,
    mode: int,
    decryptedContent
) -> None:

    try:
        decryptedContent = oc.load(StringIO(decryptedContent))
    except Exception as e:
        print(f"ERROR: could not load decrypted file content: {e}")
        return

    varDict: dict = {}
    for var in vars:
        if not var in decryptedContent:
            print(f"{var} Not found in secrets file.")
            continue

        varDict[var] = decryptedContent[var]

    try:
        templateDir = os.path.dirname(src)
        templateName = os.path.basename(src)
        env = Environment(loader=FileSystemLoader(templateDir), autoescape=True)
        template = env.get_template(templateName)
        renderedTemplate = template.render(varDict)
    except Exception as e:
        print(f'ERROR: Could not load template {src}: {e}')
        return

    add_op(
        state,
        files.put,
        name=f"Deploy secret template to {dest}",
        src=StringIO(renderedTemplate),
        dest=dest,
        user=owner,
        mode=str(mode)
    )


SECRET_HANDLERS = {
    'sops': loadSops,
    '1pass': loadOp,
    'bitwarden': loadBw,
    'hashcorp': loadVault,
}

def run_secrets_logic(state, host, choboloPath, skip, secFileO, sopsFileO):

    ChObolo = oc.load(choboloPath)
    secrets = ChObolo.get('secrets')

    if not secrets:
        print(f"No secrets declared, exiting.")
        return
    if not secrets.get('sec_mode') in SECRET_HANDLERS:
        print(f'Unsupported secret handler {secrets.get("sec_mode")}')
        return

    secFile = secFileO if secFileO else secrets.get('sec_file')
    sopsFile = sopsFileO if sopsFileO else secrets.get('sec_sops')
    templates = secrets.get('templates')

    if not all([secFile, sopsFile, templates]):
        print("WARNING: missing either sec_file, sops_file or secrets.templates, exiting.")
        return


    match secrets.get('sec_mode'):
        case 'sops':
            decryptedContent = loadSops(secFile, sopsFile)

            if not decryptedContent:
                print('Could not decrypt secrets file content.')
                return

            for t in templates:
                src: str = t.get('from')
                dest: str = t.get('to')
                owner: str = t.get('owner')
                mode: int = t.get('mode')
                vars: list[str] = t.get('vars')

                if not all([src, dest, owner, mode, vars]):
                    print(f'Secrets handling is a very dangerous role. The template {src} will not be loaded if\nnot all keys have been passed.')
                    continue

                handleTemplating(state, host, vars, src, dest, owner, mode, decryptedContent)
        case '1pass':
            print('1pass functionality still not implemented.')
            return
        case 'bitwarden':
            print('bitwarden functionality still not implemented')
            return
        case 'hashcorp':
            print('hashcorp functionality still not implemented.')
            return
        case _:
            print(f'Unexpected sec_mode: {secrets.get("sec_mode")}')
            return
