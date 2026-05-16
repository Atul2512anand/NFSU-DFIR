import os
import glob

for filepath in glob.glob("src/*.py"):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    if not content.startswith('"""'):
        name = os.basename(filepath)
        docstring = f'"""\nModule: {name}\nHandles operations related to {name.replace(".py", "")}.\n"""\n'
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(docstring + content)

print("Added module docstrings.")
