class SecretsExplain():
    _order = ['declarative', 'templates', 'sops', '1password', 'bitwarden', 'hashcorsecrets']
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
secrets:
  ...
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
            'security': "The secrets file is a file *outside* of your Ch-obolo, in the same directory as it, your Ch-obolo *points* to it. Either way, you should always commit everything inside of your Ch-obolo directory (DO NOT COMMIT UNECRYPTED SECRETS FILES.)",
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
