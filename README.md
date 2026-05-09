# Pi Wallet Auto Transfer Bot

Pi Network wallet monitoring and auto-transfer desktop app.

## Features

- Pi wallet balance monitoring
- 24-word wallet phrase support
- Automatic derivation path scan
- Destination wallet validation
- Transaction hash confirmation
- PyInstaller Windows build support
- No bip-utils dependency

## Security Warning

This program can handle a 24-word wallet phrase.  
Never upload your 24-word phrase, `pi_wallets.json`, private keys, logs, or real wallet test data to GitHub.

By default, wallet phrases should not be stored locally.

## Install

```bash
python -m venv build_env
build_env\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Run
python pi_enterprise_bot.py
Build EXE
build_no_biputils_cffi.bat

After build, distribute the whole folder:

dist/PiWalletBot

Do not distribute only PiWalletBot.exe; the \_internal folder is required.

Disclaimer

This project is not affiliated with Pi Network.
Use at your own risk. Always test with a very small amount first.
