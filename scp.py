import subprocess
import os
import sys

REMOTE_USER = "vm"
REMOTE_HOST = "192.168.122.244"
REMOTE_BASE = "~/tcpip_stack"

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"❌ Command failed: {cmd}")
        print(result.stderr)
        sys.exit(1)
    return result.stdout.strip()

def get_staged_files():
    cmd = "git diff --cached --name-only"
    output = run_cmd(cmd)
    files = output.splitlines()
    return [f for f in files if os.path.isfile(f)]

def ensure_remote_dir(remote_path):
    cmd = f'ssh {REMOTE_USER}@{REMOTE_HOST} "mkdir -p {remote_path}"'
    run_cmd(cmd)

def scp_file(local_file):
    remote_file_path = os.path.join(REMOTE_BASE, local_file)
    remote_dir = os.path.dirname(remote_file_path)

    # Create remote directory
    ensure_remote_dir(remote_dir)

    # Copy file
    cmd = f"scp {local_file} {REMOTE_USER}@{REMOTE_HOST}:{remote_file_path}"
    print(f"⬆️  Copying {local_file} → {remote_file_path}")
    run_cmd(cmd)

def main():
    files = get_staged_files()

    if not files:
        print("⚠️ No staged files found.")
        return

    print(f"📦 Found {len(files)} staged files")

    for f in files:
        scp_file(f)

    print("✅ Done.")

if __name__ == "__main__":
    main()