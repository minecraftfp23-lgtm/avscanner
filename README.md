# AvScanner — Антивирусный сканер для портфолио

Студенческий проект антивируса с GUI для поступления в колледж на кибербезопасность (Blue Team).

## Возможности

- **SHA256 хэширование** файлов для идентификации
- **VirusTotal API** проверка (опционально, по API ключу)
- **Карантин** подозрительных/вредоносных файлов
- **Автообновление** через GitHub Releases
- **Drag & Drop** файлов и папок
- **Тёмная тема** интерфейса

## Архитектура

```
av-scanner/
├── av-core/          # Rust CLI сканер (быстрый, без зависимостей)
│   ├── src/
│   │   ├── lib.rs    # Библиотека: hash_file, scan_file, scan_directory
│   │   └── main.rs   # CLI entry point (av-scan.exe)
│   └── Cargo.toml
├── av-gui/           # Python PySide6 GUI
│   ├── main.py       # Основное приложение
│   ├── bin/av-scan.exe  # Встроенный Rust бинарник
│   └── pyproject.toml
└── installer/        # NSIS/WiX установщик
```

## Сборка

### Rust CLI (av-core)

```bash
cd av-core
cargo build --release
# Результат: target/release/av-scan.exe (~766 KB)
```

### Python GUI (av-gui)

```bash
cd av-gui
pip install -e ".[dev]"
python -m PyInstaller --onefile --windowed --name av-gui \
  --add-data "bin/av-scan.exe;bin" \
  --hidden-import=PySide6.QtCore \
  --hidden-import=PySide6.QtWidgets \
  --hidden-import=PySide6.QtGui \
  main.py
# Результат: dist/av-gui.exe (~49 MB)
```

## Использование

### CLI

```bash
# Сканировать файл
av-scan.exe file suspicious.exe

# Сканировать папку
av-scan.exe dir C:\Users\Downloads

# С VirusTotal API ключом
av-scan.exe file suspicious.exe -k YOUR_API_KEY
av-scan.exe dir C:\Downloads -k YOUR_API_KEY
```

### GUI

Запустите `av-gui.exe`:
1. Перетащите файлы/папки в зону или нажмите "Сканировать папку"
2. Опционально: нажмите "🔑 VirusTotal API" для ввода ключа
3. Дождитесь результатов
4. Для malicious/suspicious файлов появится кнопка "🔒 Карантин"

Карантин хранится в `%USERPROFILE%\.avscanner\quarantine\`

## Зависимости

- **Rust**: `sha2`, `ureq` (no default features), `serde`, `anyhow`, `clap`
- **Python**: `PySide6`
- **Билд**: `PyInstaller`

## Лицензия

MIT — см. [LICENSE](installer/LICENSE.txt)