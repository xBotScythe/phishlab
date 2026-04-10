import subprocess
import os
import sys
import time
import signal
import shutil
import threading
import hashlib
from pathlib import Path

API_PORT = 8000
FRONTEND_PORT = 3000
BASE_DIR = Path(__file__).parent.absolute()
FRONTEND_DIR = BASE_DIR / "frontend"
VENV_DIR = BASE_DIR / "venv"

processes = []

def log(tag, message):
    print(f"[{tag}] {message}")

def get_env_with_venv():
    env = os.environ.copy()
    venv_bin = str(VENV_DIR / "bin")
    
    paths = [venv_bin]

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
        text=True,
        env=env
    )
    processes.append(process)

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
    
    log("SYSTEM", "Good@bye.")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

DOCKER_IMAGE = "phishing-cage"
DOCKER_TRACKED = ["Dockerfile", "detonate_url.py", "docker_requirements.txt"]
DOCKER_HASH_FILE = BASE_DIR / ".docker_build_hash"
FRONTEND_HASH_FILE = BASE_DIR / ".frontend_build_hash"
FRONTEND_TRACKED_DIRS = ["app", "components", "prisma"]
FRONTEND_TRACKED_FILES = ["package.json", "next.config.ts", "tsconfig.json", "tailwind.config.ts"]


def _docker_source_hash() -> str:
    h = hashlib.sha256()
    for name in DOCKER_TRACKED:
        path = BASE_DIR / name
        if path.exists():
            h.update(path.read_bytes())
    return h.hexdigest()


def _image_exists() -> bool:
    result = subprocess.run(
        ["docker", "images", "-q", DOCKER_IMAGE],
        capture_output=True, text=True
    )
    return bool(result.stdout.strip())


def check_docker_image():
    current_hash = _docker_source_hash()
    cached_hash = DOCKER_HASH_FILE.read_text().strip() if DOCKER_HASH_FILE.exists() else ""

    if _image_exists() and current_hash == cached_hash:
        log("SETUP", f"Docker image '{DOCKER_IMAGE}' is up to date.")
        return

    reason = "image not found" if not _image_exists() else "source files changed"
    log("SETUP", f"Building Docker image '{DOCKER_IMAGE}' ({reason})...")
    if not run_command(["docker", "build", "-t", DOCKER_IMAGE, "."]):
        log("ERROR", "Docker build failed. Detonation will not work.")
        sys.exit(1)

    DOCKER_HASH_FILE.write_text(current_hash)
    log("SETUP", "Docker image built successfully.")


def _frontend_source_hash() -> str:
    h = hashlib.sha256()
    for name in FRONTEND_TRACKED_FILES:
        path = FRONTEND_DIR / name
        if path.exists():
            h.update(path.read_bytes())
    for dir_name in FRONTEND_TRACKED_DIRS:
        for path in sorted((FRONTEND_DIR / dir_name).rglob("*")):
            if path.is_file():
                h.update(path.read_bytes())
    return h.hexdigest()


def check_frontend_build():
    current_hash = _frontend_source_hash()
    cached_hash = FRONTEND_HASH_FILE.read_text().strip() if FRONTEND_HASH_FILE.exists() else ""
    next_dir = FRONTEND_DIR / ".next"

    if next_dir.exists() and current_hash == cached_hash:
        log("SETUP", "Frontend build is up to date.")
        return

    reason = "no build found" if not next_dir.exists() else "source files changed"
    log("SETUP", f"Building frontend ({reason})...")
    if not run_command(["npm", "run", "build"], cwd=FRONTEND_DIR):
        log("ERROR", "Frontend build failed.")
        sys.exit(1)

    FRONTEND_HASH_FILE.write_text(current_hash)
    log("SETUP", "Frontend built successfully.")


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
    if not check_python_setup():
        log("SETUP", "Python dependencies missing. Installing...")
        run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    else:
        log("SETUP", "Python dependencies already satisfied.")

    if not check_node_setup():
        log("SETUP", "Frontend dependencies missing. Running npm install...")
        if not run_command(["npm", "install"], cwd=FRONTEND_DIR):
            log("ERROR", "npm install failed. Please check your Node.js installation.")
            sys.exit(1)
    else:
        log("SETUP", "Frontend dependencies already satisfied.")

def main():
    log("SYSTEM", "Initializing PhishLab Environment...")

    python_ok = check_python_setup()
    node_ok = check_node_setup()

    if not (python_ok and node_ok):
        log("SYSTEM", "Environment needs initialization...")
        perform_setup()
    else:
        log("SYSTEM", "Environment already configured. Skipping setup.")

    check_docker_image()
    check_frontend_build()

    log("SYSTEM", "Starting Database (Docker)...")
    if not run_command(["docker", "compose", "up", "-d", "db"]):
        log("ERROR", "Failed to start Docker. Is Docker Desktop running?")
        sys.exit(1)

    time.sleep(2)

    log("SYSTEM", "Syncing Database Schema (Prisma)...")
    schema_path = str(FRONTEND_DIR / "prisma" / "schema.prisma")
    if not run_command(["npx", "prisma@5.17.0", "db", "push", "--schema", schema_path], cwd=FRONTEND_DIR, shell=False):
        log("ERROR", "Prisma sync failed.")
        sys.exit(1)

    start_process([sys.executable, "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", str(API_PORT)], "API")
    start_process(["npm", "run", "start"], "FRONTEND", cwd=FRONTEND_DIR)

    log("SYSTEM", "--------------------------------------------------")
    log("SYSTEM", f"API is available at: http://localhost:{API_PORT}")
    log("SYSTEM", f"Frontend is available at: http://localhost:{FRONTEND_PORT}")
    log("SYSTEM", "Press CTRL+C to stop all services.")
    log("SYSTEM", "--------------------------------------------------")

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
