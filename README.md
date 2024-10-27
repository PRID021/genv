# Install builder

```sh
pip install pyinstaller
pyinstaller --onefile --icon=path/to/icon.icns --name genv main.py
rm -rf build/ genv..spec
chmod +x ./genv

```

Copy Identity files to `~/.ssh` folder and add env to `PATH`

```sh
code  ~/.zshrc
```

```sh
export PATH="/Users/{your_mac}/genv/dist:$PATH"
```

Reload profile

```sh
source ~/.zshrc
```

Test command

```sh
genv
```
