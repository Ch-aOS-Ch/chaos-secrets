import os
from io import StringIO
from pathlib import Path
from typing import Any

import yaml
from chaos.lib.args.dataclasses import Delta, ResultPayload
from chaos.lib.roles.role import Role
from jinja2 import Environment, FileSystemLoader
from pyinfra.api.operation import add_op
from pyinfra.facts.server import Command, Home
from pyinfra.operations import files


class SecretsRole(Role):
    """
    Role to manage secret files based on templates.
    Centralizes templates at ~/.config/chaos/templates.
    """

    def __init__(self):
        super().__init__(
            name="Manage Secrets via Templates",
            needs_secrets=True,
            necessary_chobolo_keys=["secrets"],
            necessary_secret_dict_keys=["."],
        )

    def get_context(
        self, state, host, chobolo: dict = {}, secrets: dict[str, Any] = {}
    ) -> dict[str, Any]:
        context = {
            "chobolo": chobolo,
            "secrets": secrets.get(".", {}),
        }

        state_file = "/var/lib/chaos/secrets.yml"
        previous_state_content = host.get_fact(
            Command, f"cat {state_file} || true", _sudo=True, _sudo_user="root"
        )
        previous_state = (
            yaml.safe_load(previous_state_content)
            if previous_state_content
            else {"managed_files": []}
        )
        context["previous_state"] = previous_state
        return context

    def delta(self, context: dict[str, Any] = {}) -> Delta:
        chobolo = context.get("chobolo", {})
        secrets = context.get("secrets", {})
        previous_state = context.get("previous_state", {})

        raw_previous_files = previous_state.get("managed_files", [])
        previously_managed_files = set()

        if raw_previous_files and isinstance(raw_previous_files[0], str):
            pass

        elif raw_previous_files:
            for f_info in raw_previous_files:
                previously_managed_files.add((f_info["path"], f_info["owner"]))

        secrets_config = chobolo.get("secrets", {})
        templates = secrets_config.get("templates", [])

        desired_managed_files = set()
        new_state_list_of_dicts = []
        to_add = []
        invalid_templates = []
        missing_secrets = []

        for t in templates:
            src = t.get("from")
            dest = t.get("to")
            owner = t.get("owner")
            mode = t.get("mode")
            vars_list = t.get("vars", [])
            escape = t.get("escape", True)

            required = [src, dest, owner, mode, vars_list]
            if any(k is None for k in required):
                invalid_templates.append(
                    f"Missing required fields for template src={src}, dest={dest}"
                )
                continue

            if dest.startswith("/") or ".." in dest:
                invalid_templates.append(
                    f"Invalid pathing in dest={dest}. Avoid '..' and leading '/'."
                )
                continue

            if src.startswith("/") or ".." in src:
                invalid_templates.append(
                    f"Invalid pathing in src={src}. Avoid '..' and leading '/'."
                )
                continue

            missing = [v for v in vars_list if v not in secrets]
            if missing:
                missing_secrets.append(f"Template {src} is missing secrets: {missing}")
                continue

            desired_managed_files.add((dest, owner))
            new_state_list_of_dicts.append({"path": dest, "owner": owner})

            to_add.append(
                {
                    "src": src,
                    "dest": dest,
                    "owner": owner,
                    "mode": mode,
                    "vars": vars_list,
                    "escape": escape,
                }
            )

        files_to_remove_set = previously_managed_files - desired_managed_files
        to_remove = [
            {"path": path, "owner": owner} for path, owner in files_to_remove_set
        ]

        to_add_display = [f"~/{t['dest']} (from {t['src']})" for t in to_add]
        to_remove_display = [
            f"~/{r['path']} (for user {r['owner']})" for r in to_remove
        ]

        return Delta(
            to_add={"templates": to_add_display} if to_add_display else {},
            to_remove={"files": to_remove_display} if to_remove_display else {},
            metadata={
                "new_state": new_state_list_of_dicts,
                "secrets": secrets,
                "to_add_raw": to_add,
                "to_remove_raw": to_remove,
                "invalid_templates": invalid_templates,
                "missing_secrets": missing_secrets,
            },
        )

    def plan(self, state, host, delta: Delta = Delta()) -> ResultPayload:
        errors = []

        invalid_templates = delta.metadata.get("invalid_templates", [])
        if invalid_templates:
            errors.extend(invalid_templates)

        missing_secrets = delta.metadata.get("missing_secrets", [])
        if missing_secrets:
            errors.extend(missing_secrets)

        to_remove = delta.metadata.get("to_remove_raw", [])
        to_add = delta.metadata.get("to_add_raw", [])
        new_state = delta.metadata.get("new_state", [])
        secrets = delta.metadata.get("secrets", {})

        for item in to_remove:
            path = item["path"]
            owner = item["owner"]

            home_dir = host.get_fact(Home, user=owner)
            if not home_dir:
                errors.append(f"Could not determine home directory for user {owner}")
                continue

            clean_path = path[2:] if path.startswith("./") else path
            full_path = os.path.join(home_dir, clean_path)

            add_op(
                state,
                files.file,
                name=f"Removing obsolete secret file: {full_path} for user {owner}",
                path=full_path,
                host=host,
                present=False,
                _sudo=True,
                _sudo_user=owner,
            )

        config_dir = os.getenv("CHAOS_CONFIG_DIR", Path.home() / ".config" / "chaos")
        templates_base_dir = os.path.join(config_dir, "templates")

        for item in to_add:
            src = item["src"]
            dest = item["dest"]
            owner = item["owner"]
            mode = item["mode"]
            vars_list = item["vars"]
            escape = item["escape"]

            var_dict = {v: secrets[v] for v in vars_list}

            try:
                full_template_path = os.path.join(templates_base_dir, src)
                template_dir = os.path.dirname(full_template_path)
                template_name = os.path.basename(full_template_path)

                env = Environment(
                    loader=FileSystemLoader(template_dir), autoescape=escape
                )
                template = env.get_template(template_name)
                rendered_template = template.render(var_dict)

                home_dir = host.get_fact(Home, user=owner)
                if not home_dir:
                    errors.append(
                        f"Could not determine home directory for user {owner}. Skipping template {src}."
                    )
                    continue

                clean_dest = dest[2:] if dest.startswith("./") else dest
                final_dest = os.path.join(home_dir, clean_dest)

                add_op(
                    state,
                    files.put,
                    name=f"Deploy secret template to {final_dest} for user {owner}",
                    src=StringIO(rendered_template),
                    host=host,
                    dest=final_dest,
                    user=owner,
                    mode=oct(mode)[2:] if isinstance(mode, int) else str(mode),
                    _sudo=True,
                    _sudo_user=owner,
                )
            except Exception as e:
                errors.append(f"Could not load or render template {src}: {e}")

        if not to_add and not to_remove and not new_state:
            return ResultPayload(
                success=len(errors) == 0, message=[], error=errors, data={}
            )

        state_file = "/var/lib/chaos/secrets.yml"
        state_dir = os.path.dirname(state_file)

        sorted_new_state = sorted(new_state, key=lambda x: (x["owner"], x["path"]))
        new_state_data = {"managed_files": sorted_new_state}
        yaml_content = yaml.dump(new_state_data)

        add_op(
            state,
            files.directory,
            name="Ensuring secrets state directory exists",
            path=state_dir,
            host=host,
            present=True,
            user="root",
            _sudo=True,
            mode="0700",
        )

        add_op(
            state,
            files.put,
            name="Recording new secrets state",
            src=StringIO(yaml_content),
            host=host,
            dest=state_file,
            user="root",
            _sudo=True,
            mode="0600",
        )

        return ResultPayload(
            success=len(errors) == 0, message=[], error=errors, data={}
        )
