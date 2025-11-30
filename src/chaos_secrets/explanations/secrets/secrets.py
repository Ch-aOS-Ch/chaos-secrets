class SecretsExplain():
    _order = ['declarative', 'templates', 'sops', '1password', 'bitwarden', 'hashcorp']
    def explain_secrets(self, detail_level='basic'):
        return {
            'concept': 'Secret keys management.',
            'what': "'Secrets' are, as their name implies, secret values that require caution as to how they're handled, since one misstep with them could cause irreversible damage to companies or even people. Secret managers came as a solution to this problem, as they allow you to encrypt and decrypt all your keys safely.",
            'why': "To allow for version management of secrets! Imagine this: you've just reinstalled an OS and now you have to get a new ssh key, since the private one is now gone. You will also need to get all of your work passwords back, since they were not version controlled or backed up. Oh, and also your GPG keys! With a secret manager, you can have all your secrets version controlled and you'd only need to backup one singular secret key, and that'd be it.",
            'how': "Usually utilizing some sort of GPG key or other types of bijector keys, most secret managers encrypt values inside of files utilizing this key and then applying lots of different encryption methods. This plugin accepts sops only, but I intend to extend it to 1Password, Bitwarden, and HashiCorp Vault too, since they're easy to use.",
            'commands': ['git', 'sops', 'op', 'bw', 'vault'],
            'examples': [
                {
                    'yaml': """secrets:
  sec_mode: sops
  sec_file: /path/to/sec/file.yaml
  sops_file: /path/to/sops/config.yaml
  templates:
    - from: /path/to/my/template.j2
      to: /path/where/I/want/my/secrets
      owner: dex
      mode: 0600
      escape: False
      vars:
        - var-that-exists-in-my-sec_file
        - var-that-exists-in-my-sec_file2
        - priv_ssh
""",
                }
            ],
            'equivalent': """# Decrypt the file to view the values
sops --config .../sops/config.yaml -d .../sec/file.yaml

# Here, you'd copy var1, var2, and priv_ssh to put them somewhere for later.

# And now, you'd manually copy and paste the secrets into the final file.
nvim /path/where/I/want/my/secrets
""",
            'security': "CRITICAL: The entire secret management process is highly sensitive. The final rendered files will contain plaintext secrets. Ensure the `mode` is set to `0600` or similarly restrictive permissions. The underlying encryption key (e.g., your GPG private key for `sops`) is the master key to all your secrets and must be protected and backed up securely.",
            'learn_more': ['Secrets on Arch Wiki', 'man sops']
        }

    def explain_templates(self, detail_level='basic'):
        return {
            'concept': 'Secret Templating with Jinja2',
            'what': 'Templating is the process of taking a template file (like a .j2 file) and injecting values (in this case, decrypted secrets) into it to generate a final, ready-to-use configuration file.',
            'why': "To separate a configuration file's structure from its sensitive data. This allows you to version the template file in Git without exposing passwords or API keys. It also lets you reuse the same secret in multiple configuration files without duplication.",
            'how': "The `secrets` role reads your `from` file, finds the variables you listed in `vars`, fetches their corresponding values from the decrypted secrets file, and uses the Jinja2 engine to render the final file at the `to` location, applying the `owner` and `mode` you specified.",
            'examples': [
                {
                    'yaml': """# In your Ch-obolo, you define the list of templates:
templates:
  - from: /path/to/my/template.j2
    to: /etc/app/config.conf
    owner: dex
    mode: 0600
    vars:
      - api_key
      - database_password
""",
                }
            ],
            'security': "CRITICAL: The output of this process is a file containing plaintext secrets. It is your responsibility to define a secure `to` path and set restrictive permissions using `mode: '0600'` and the correct `owner`. Never template secrets to a world-readable location.",
            'learn_more': ['Jinja2 Documentation']
        }

    def explain_declarative(self, detail_level='basic'):
        return {
            'concept': 'Declarative Secret Management',
            'what': 'It means you describe the "desired end state" of your secrets in a configuration file (the Ch-obolo file), and the tool (Ch-aOS) handles the steps required to achieve that state. You declare *what* you want, not *how* to do it.',
            'why': 'It makes your configuration reproducible, version-controllable, and much easier to understand. Instead of following a manual script of steps (copy, paste, set permissions), you have a single source of truth that describes where each secret should be.',
            'how': 'You define the `secrets` block in your Ch-obolo. The tool reads this "declaration," decrypts the secrets in memory, renders the templates, and applies the files to the system. If you remove an item from the list, the tool knows it\'s no longer desired and can clean it up in the future.',
            'security': "By declaring your secrets, your Ch-obolo file becomes a map to your sensitive information. While it doesn't contain the secrets themselves, it describes how to access and deploy them. Protect your Ch-obolo file and associated templates as you would any other critical configuration.",
            'equivalent': """# The imperative (non-declarative) approach would be:
# 1. Decrypt the file manually
sops -d secrets.yml > /tmp/temp_secrets.yml

# 2. Read the values you need
API_KEY=$(grep api_key /tmp/temp_secrets.yml | awk '{print $2}')
DB_PASS=$(grep db_pass /tmp/temp_secrets.yml | awk '{print $2}')

# 3. Create the configuration file manually
echo "key = $API_KEY" > /etc/app/config.conf
echo "pass = $DB_PASS" >> /etc/app/config.conf

# 4. Set permissions manually
chmod 0600 /etc/app/config.conf
chown dex /etc/app/config.conf

# 5. Clean up the temporary file
rm /tmp/temp_secrets.yml
""",
        }

    def explain_sops(self, detail_level='basic'):
        return {
            'concept': 'Sops: Secrets OPerationS',
            'what': '`sops` is an open-source tool for editing text files that contain secrets. It was designed to make managing secrets in version control systems (like Git) safer and easier by encrypting only the values within a file (e.g., YAML, JSON), but not the keys.',
            'why': 'It is the default and currently the only backend supported by this plugin. It is a flexible and widely-used tool that integrates with GPG, AWS KMS, GCP KMS, and others, allowing you to choose your preferred encryption method.',
            'how': 'Ch-aOS invokes the `sops -d` command using the `sec_file` and `sops_file` paths to decrypt the content in memory. Your secrets are never written to disk in plaintext by the tool itself (only in the final rendered template). The `.sops.yaml` file (defined in `sops_file`) tells `sops` which key (e.g., your GPG key) should be used.',
            'security': "The security of `sops` depends entirely on the protection of the master encryption key it uses (e.g., GPG private key, AWS KMS key). If this key is compromised, all your secrets are exposed. Never commit unencrypted private keys to version control.",
            'learn_more': ['man sops', 'Sops GitHub Repository']
        }

    def explain_1password(self, detail_level='basic'):
        return {
            'concept': '1Password Integration (Future)',
            'status': 'NOT YET IMPLEMENTED',
            'what': '1Password is a popular cloud-based password manager. A future integration would allow Ch-aOS to fetch secrets directly from your 1Password vault instead of from a local file.',
            'why': 'For users who already use 1Password as their primary secret store, this would avoid duplicating secrets in a separate `sops` file, maintaining a single source of truth.',
            'how': 'When implemented, you will be able to set `sec_mode: 1password`. The plugin will use the 1Password CLI (`op`) to authenticate and fetch the required values for the templates.',
            'security': "When this integration is implemented, it will require an authentication token or session key. This token is a secret itself and must be handled securely. It should never be hardcoded in your Ch-obolo file.",
        }

    def explain_bitwarden(self, detail_level='basic'):
        return {
            'concept': 'Bitwarden Integration (Future)',
            'status': 'NOT YET IMPLEMENTED',
            'what': 'Bitwarden is a popular open-source password manager, which can be self-hosted or used as a cloud service. A future integration would allow Ch-aOS to fetch secrets directly from your vault.',
            'why': 'For users who already use Bitwarden as their primary secret store, this would avoid duplicating secrets in a separate `sops` file.',
            'how': 'When implemented, you will be able to set `sec_mode: bitwarden`. The plugin will use the Bitwarden CLI (`bw`) to authenticate and fetch the required values for the templates.',
            'security': "When this integration is implemented, it will require an authentication token or session key. This token is a secret itself and must be handled securely. It should never be hardcoded in your Ch-obolo file.",
        }

    def explain_hashcorp(self, detail_level='basic'):
        return {
            'concept': 'HashiCorp Vault Integration (Future)',
            'status': 'NOT YET IMPLEMENTED',
            'what': 'HashiCorp Vault is a tool specializing in secrets management for large-scale and production environments. A future integration would allow Ch-aOS to fetch secrets directly from a Vault instance.',
            'why': 'For more advanced or enterprise use-cases where Vault is already the standard tool for secrets management.',
            'how': 'When implemented, you will be able to set `sec_mode: hashcorp`. The plugin will use the Vault CLI (`vault`) to authenticate and fetch the required values for the templates.',
            'security': "When this integration is implemented, it will require an authentication token or session key. This token is a secret itself and must be handled securely. It should never be hardcoded in your Ch-obolo file.",
        }

