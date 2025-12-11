import os
import sys
from pyinfra.api.operation import add_op
from pyinfra.operations import files

import sys

from jinja2 import Environment, FileSystemLoader
import subprocess

from omegaconf import DictConfig, OmegaConf as oc
from io import StringIO

def loadSops(secFile, secSopsO):
    try:
        result=subprocess.run(
            ['sops', '--config', secSopsO, '-d', secFile],
            capture_output=True,
            text=True,
            check=True
        )
        try:
            return oc.load(StringIO(result.stdout))
        except Exception:
            return None
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
    choboloPath,
    vars: list[str],
    src: str,
    dest: str,
    owner: str,
    mode: int,
    decryptedContent,
    escape: bool,
) -> None:

    varDict: dict = {}

    for var in vars:
        if not var in decryptedContent:
            print(f"FATAL: {var} Not found in secrets file, aborting.")
            sys.exit(1)

        varDict[var] = decryptedContent[var]

    try:
        choboloDir = os.path.dirname(choboloPath)
        fullTemplatePath = os.path.join(choboloDir, src)
        templateDir = os.path.dirname(fullTemplatePath)
        templateName = os.path.basename(fullTemplatePath)
        env = Environment(loader=FileSystemLoader(templateDir), autoescape=escape)
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
        mode=str(mode) if isinstance(mode, int) else mode
    )


def run_secrets_logic(state, host, choboloPath, skip, secFileO, sopsFileO):

    ChObolo = oc.load(choboloPath)
    secrets = ChObolo.get('secrets')

    if not secrets:
        print(f"No secrets declared, exiting.")
        return

    secFile = secFileO if secFileO else secrets.get('sec_file')
    sopsFile = sopsFileO if sopsFileO else secrets.get('sec_sops')
    templates = secrets.get('templates')
    if not isinstance(templates, list):
        print("ERROR: temoplates must be a list. Aborting.")
        sys.exit(1)

    if not all([secFile, sopsFile, templates]):
        print("WARNING: missing either sec_file, sops_file or secrets.templates, exiting.")
        return


    match secrets.get('sec_mode'):
        case 'sops':
            decryptedContent = loadSops(secFile, sopsFile)
            if not isinstance(decryptedContent, (dict, DictConfig)):
                print("FATAL: Decrypted file is not a dict.")
                sys.exit(1)

            if not decryptedContent:
                print('Could not decrypt secrets file content.')
                return

            for t in templates:
                src: str = t.get('from')
                dest: str = t.get('to')
                owner: str = t.get('owner')
                mode: int = t.get('mode')
                vars: list[str] = t.get('vars')
                escape: bool = t.get('escape', False)

                required=[src, dest, owner, mode, vars]
                if any(k is None for k in required):
                    print(f'Secrets handling is a very dangerous role. The template {src} will not be loaded if\nnot all keys have been passed.')
                    continue

                if dest.startswith('/') or '..' in dest:
                    print("Invalid pathing. Avoid using '..' and do not ever use / at the start.")
                    continue

                if src.startswith('/') or '..' in src:
                    print("Invalid pathing. Avoid using '..' and do not ever use / at the start.")
                    continue

                handleTemplating(state, choboloPath, vars, src, dest, owner, mode, decryptedContent, escape)
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
