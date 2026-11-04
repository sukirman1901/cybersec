"""Install scanner CLIs in isolated venvs, never downgrade the MCP environment."""
import argparse
import concurrent.futures
import pathlib
import platform
import subprocess
import sys
import venv

PACKAGES = {'bandit': 'bandit', 'semgrep': 'semgrep', 'sslyze': 'sslyze', 'certipy': 'certipy-ad'}
if sys.platform == 'darwin' and platform.machine() == 'x86_64':
    # 1.183.0 explicitly removed Intel macOS semgrep-core binaries.
    PACKAGES['semgrep'] = 'semgrep<1.183.0'
ROOT = pathlib.Path.home() / '.local/share/cybersec/tools'


def install(name):
    directory = ROOT / name
    venv.EnvBuilder(with_pip=True).create(directory)
    subprocess.run([str(directory / 'bin/python'), '-m', 'pip', 'install', PACKAGES[name]], check=True)
    subprocess.run([str(directory / 'bin/python'), '-m', 'pip', 'check'], check=True)
    return name


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tools', nargs='+', choices=PACKAGES)
    args = parser.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for name in pool.map(install, args.tools):
            print('Installed isolated CLI:', name, flush=True)
