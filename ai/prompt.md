Write a python program for the Mac to diagnose why inbound SSH connections on port 22 do not work.
Structure the application as a series of networking tests. Organize the tests from most fundamental to most focused / narrow.

Use the `subprocess` library module to system run commands. A sample system command should look like this (in this case to list a directory):
```
import subprocess

def run_command():
    cmd = ["ls", "-alrt"] # Change this command to fit situation
    print(f"{cmd = }")
    result = subprocess.run(
        cmd, encoding='utf-8', check=True,
        capture_output=True,
        cwd=".",
    )

    if result.returncode == 0:
        log_output = result.stdout
    else:
        raise Exception(f"command failed {cmd}")
``` 

Create directory path variables from the `pathlib` system library.
