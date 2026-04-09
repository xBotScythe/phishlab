import subprocess
import os
import sys
import time
import signal
import shutil
import threading
from pathlib import Path

# config
API_PORT = 8000
FRONTEND_PORT = 3000
BASE_DIR = Path(__file__).parent.absolute()
FRONTEND_DIR = BASE_DIR / "frontend"
VENV_DIR = BASE_DIR / "venv"

# process state
processes = []

def log(tag, message):
    print(f"[{tag}] {message}")

def get_env_with_venv():
    env = os.environ.copy()
    venv_bin = str(VENV_DIR / "bin")
    
    # system paths to ensure are present (order-sensitive prepending)
    paths = [venv_bin]
    
    # add brew path on mac
    if sys.platform == "darwin":
        brew_bin = "/opt/homebrew/bin"
        if os.path.exists(brew_bin):
            paths.append(brew_bin)
        if "/usr/local/bin" not in paths:
            paths.append("/usr/local/bin")

    current_path = env.get("PATH", "")
    for p in paths:
        if p not in current_path:
            current_path = f"{p}{os.pathsep}{current_path}"
    
    env["PATH"] = current_path
    return env

def run_command(cmd, cwd=BASE_DIR, shell=False, check=True):
    env = get_env_with_venv()
    try:
        subprocess.run(cmd, cwd=cwd, shell=shell, check=check, env=env)
        return True
    except subprocess.CalledProcessError as e:
        log("ERROR", f"Command failed: {cmd} in {cwd}. Error: {e}")
        return False

def stream_logs(process, tag):
    for line in iter(process.stdout.readline, ''):
        print(f"[{tag}] {line.strip()}")

def start_process(cmd, tag, cwd=BASE_DIR):
    log(tag, f"Starting: {' '.join(cmd)}")
    env = get_env_with_venv()

    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True,  # binary mode fix
        env=env
    )
    processes.append(process)
    
    # log streamer
    thread = threading.Thread(target=stream_logs, args=(process, tag), daemon=True)
    thread.start()
    return process

def cleanup(sig=None, frame=None):
    log("SYSTEM", "Shutting down all services...")
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=5)
        except:
            p.kill()
    
    # stop docker? not for now
    
    log("SYSTEM", "Good@bye.")
    sys.exit(0)

# signals
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# setup logic
def check_python_setup():
    try:
        import fastapi
        import uvicorn
        import prisma
        return True
    except ImportError:
        return False

def check_node_setup():
    return (FRONTEND_DIR / "node_modules").exists()

def perform_setup():
    # python deps
    if not check_python_setup():
        log("SETUP", "Python dependencies missing. Installing...")
        run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    else:
        log("SETUP", "Python dependencies already satisfied.")
    
    # node deps
    if not check_node_setup():
        log("SETUP", "Frontend dependencies missing. Running npm install...")
        if not run_command(["npm", "install"], cwd=FRONTEND_DIR):
            log("ERROR", "npm install failed. Please check your Node.js installation.")
            sys.exit(1)
    else:
        log("SETUP", "Frontend dependencies already satisfied.")

# main entry
def main():
    log("SYSTEM", "Initializing PhishLab Environment...")

    # init check
    python_ok = check_python_setup()
    node_ok = check_node_setup()

    if not (python_ok and node_ok):
        log("SYSTEM", "Environment needs initialization...")
        perform_setup()
    else:
        log("SYSTEM", "Environment already configured. Skipping setup.")
    
    # database (docker)
    log("SYSTEM", "Starting Database (Docker)...")
    if not run_command(["docker", "compose", "up", "-d", "db"]):
        log("ERROR", "Failed to start Docker. Is Docker Desktop running?")
        sys.exit(1)
    
    # wait for db
    time.sleep(2)

    # sync schema
    log("SYSTEM", "Syncing Database Schema (Prisma)...")
    schema_path = str(FRONTEND_DIR / "prisma" / "schema.prisma")
    if not run_command(["npx", "prisma@5.17.0", "db", "push", "--schema", schema_path], cwd=FRONTEND_DIR, shell=False):
        log("ERROR", "Prisma sync failed.")
        sys.exit(1)
    
    # core services
    log("SYSTEM", "Launching Core Services...")
    
    # api (uvicorn)
    start_process([sys.executable, "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", str(API_PORT)], "API")
    
    # frontend (next.js)
    start_process(["npm", "run", "dev"], "FRONTEND", cwd=FRONTEND_DIR)

    log("SYSTEM", "--------------------------------------------------")
    log("SYSTEM", f"API is available at: http://localhost:{API_PORT}")
    log("SYSTEM", f"Frontend is available at: http://localhost:{FRONTEND_PORT}")
    log("SYSTEM", "Press CTRL+C to stop all services.")
    log("SYSTEM", "--------------------------------------------------")

    # keep alive
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
