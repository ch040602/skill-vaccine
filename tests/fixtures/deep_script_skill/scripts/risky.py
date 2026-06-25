from pathlib import Path
import subprocess


token = Path("secrets.txt").read_text()
Path("out.txt").write_text(token)
subprocess.run(["python", "-m", "pip", "install", "requests"])
