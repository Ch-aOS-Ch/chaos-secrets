import os
import sys
from pyinfra.api.operation import add_op
from pyinfra.operations import files
from pyinfra.facts.server import Command
import yaml

from jinja2 import Environment, FileSystemLoader

from omegaconf import DictConfig, OmegaConf as oc
from io import StringIO

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

        dest = f'~/{dest}'
    except Exception as e:
        print(f'ERROR: Could not load template {src}: {e}')
        return

    add_op(
        state,
        files.put,
        name=f"Deploy secret template to {dest} for user {owner}",
        src=StringIO(renderedTemplate),
        dest=dest,
        user=owner,
        mode=str(mode) if isinstance(mode, int) else mode,
        _sudo=True,
        _sudo_user=owner
    )


def handleReconcile(host, state, choboloPath, skip):

    stateFile = "/var/lib/chaos/secrets.yml"
    previous_state_content = host.get_fact(Command, f"cat {stateFile} || true", _sudo=True, _sudo_user='root')
    previous_state = yaml.safe_load(previous_state_content) if previous_state_content else {"managed_files": []}

    raw_previous_files = previous_state.get("managed_files", [])
    previously_managed_files = set()

    if raw_previous_files and isinstance(raw_previous_files[0], str):
        print("WARNING: Old state file format detected. Reconciliation for user-specific files may not work correctly. The state will be updated to the new format.")

    elif raw_previous_files:
        for f_info in raw_previous_files:
            previously_managed_files.add((f_info['path'], f_info['owner']))

    ChObolo = oc.load(choboloPath)
    secrets_config = ChObolo.get('secrets', {})
    templates = secrets_config.get('templates', [])

    desired_managed_files = set()
    new_state_list_of_dicts = []
    for t in templates:
        dest_path = t.get('to')
        owner = t.get('owner')
        if dest_path is None or owner is None:
            continue
        if dest_path.startswith('/') or '..' in dest_path:
            print(f"Invalid pathing in template destination: '{dest_path}'. Avoid using '..' and do not ever use / at the start. Skipping.")
            continue

        desired_managed_files.add((dest_path, owner))
        new_state_list_of_dicts.append({'path': dest_path, 'owner': owner})

    files_to_remove = previously_managed_files - desired_managed_files
    if files_to_remove:
        print("The following secret files will be removed:")
        for path, owner in files_to_remove:
            print(f" - ~/{path} (for user {owner})")

        confirm = "y" if skip else input("\nIs This correct (Y/n)? ")
        if confirm.lower() in ["y", "yes", "", "s", "sim"]:
            for file_path, owner in files_to_remove:
                tilde_path = f"~/{file_path}"
                add_op(
                    state,
                    files.file,
                    name=f"Removing obsolete secret file: {tilde_path} for user {owner}",
                    path=tilde_path,
                    present=False,
                    _sudo=True,
                    _sudo_user=owner
                )
    state_dir = os.path.dirname(stateFile)

    sorted_new_state = sorted(new_state_list_of_dicts, key=lambda x: (x['owner'], x['path']))
    new_state_data = {"managed_files": sorted_new_state}
    yaml_content = yaml.dump(new_state_data)

    add_op(
        state, files.directory, name="Ensuring secrets state directory exists",
        path=state_dir, present=True, user='root', _sudo=True, mode='0700'
    )

    add_op(
        state, files.put, name="Recording new secrets state",
        src=StringIO(yaml_content),
        dest=stateFile,
        user='root', _sudo=True,
        mode='0600'
    )

def run_secrets_logic(state, host, choboloPath, skip, decrypted_secrets=None):

    handleReconcile(host, state, choboloPath, skip)

    ChObolo = oc.load(choboloPath)
    secrets = ChObolo.get('secrets')

    if not secrets:
        print(f"No secrets declared, exiting.")
        return

    templates = secrets.get('templates')
    if not isinstance(templates, list):
        print("ERROR: templates must be a list. Aborting.")
        sys.exit(1)

    if not templates:
        print("WARNING: missing secrets.templates, exiting.")
        return

    decryptedContent = None
    if decrypted_secrets:
        try:
            decryptedContent = oc.load(StringIO(decrypted_secrets))
        except Exception as e:
            print(f"FATAL: Decrypted secret content is not valid YAML/JSON: {e}")
            sys.exit(1)

    if not decryptedContent or not isinstance(decryptedContent, (dict, DictConfig)):
        print("FATAL: Decrypted file is not a dict or content is empty.")
        sys.exit(1)

    for t in templates:
        src: str = t.get('from')
        dest: str = t.get('to')
        owner: str = t.get('owner')
        mode: int = t.get('mode')
        vars: list[str] = t.get('vars')
        escape: bool = t.get('escape', True)

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