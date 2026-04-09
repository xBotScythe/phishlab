import subprocess
import atexit
import time
import requests

_ollama_process = None

def start_ollama():
    global _ollama_process
    try:
        # check if running
        requests.get("http://127.0.0.1:11434/", timeout=1)
        # already running
        return
    except Exception:
        pass

    if not _ollama_process:
        try:
            print("Starting ollama serve...")
            _ollama_process = subprocess.Popen(
                ["ollama", "serve"], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            # wait for spin up
            time.sleep(3)
        except FileNotFoundError:
            print("Error: Ollama executable not found. Is it installed?")
            return
        except Exception as e:
            print(f"Warning: Failed to start ollama serve automatically: {e}")
            return


def stop_ollama():
    global _ollama_process
    if _ollama_process:
        try:
            _ollama_process.terminate()
            _ollama_process.wait(timeout=3)
        except Exception:
            pass
        _ollama_process = None

# auto shutdown hook
atexit.register(stop_ollama)
