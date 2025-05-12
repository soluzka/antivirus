# Windows Defender

An advanced antivirus system with real-time protection, network monitoring, and threat detection capabilities.

## Features

- Real-time file scanning and monitoring
- Network traffic analysis and threat detection
- DNS server with malicious domain blocking
- Advanced threat detection using machine learning
- Phishing detection and protection
- File encryption and secure storage
- Automated signature updates
- Web interface for management

## Installation

1. Install Python 3.8 or higher
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. For development (optional):
   - Run the automatic setup script with admin privileges:
   ```bash
   python setup_redis.py
   ```
   - Restart your computer when prompted

4. For EXE build:
   - Run the automatic setup script with admin privileges:
   ```bash
   python setup_redis.py
   ```
   - Restart your computer when prompted

**Automatic Setup Notes:**
- The script will download and install Redis automatically
- It will set up the `REDIS_HOME` environment variable
- It will add Redis to your system PATH
- You must run the script with administrator privileges
- You must restart your computer after running the script

## Building EXE Version

To build the EXE version with Redis support:

1. Download Redis for Windows and extract it to `C:\Redis`
2. Set up environment variable:
   - Name: `REDIS_HOME`
   - Value: `C:\Redis`
3. Build the EXE using PyInstaller:
```bash
python build_config.py
```

The EXE will automatically:
1. Check for Redis in `C:\Redis` (via environment variable)
2. If found, use it for persistent rate limiting
3. If not found, fall back to in-memory storage

**Storage Behavior:**
- **Redis Storage (Recommended):**
  - Data persists between application restarts
  - Stored in Redis database on disk
  - Maintains rate limits across restarts
  - Location: Redis database (configured via `REDIS_HOME`)

- **In-Memory Storage (Fallback):**
  - Data stored in RAM only
  - All rate limit data is lost when application restarts
  - No files are created on disk
  - Only for development/testing

**Note:**
- Always use Redis in production for persistent rate limiting
- In-memory storage is for development only
- Rate limits will persist between restarts only when using Redis

4. Run the application:
```bash
python app.py
```

The application will start a web server on http://127.0.0.1:5000

## Building EXE Version

To build the EXE version with embedded Redis:

1. Download Redis for Windows and extract it to `redis` folder in the project root
2. Build the EXE using PyInstaller:
```bash
pyinstaller --onefile --windowed --icon=app.ico --name="Windows Defender" app.py
```

The EXE will automatically use the embedded Redis server if available.

**Note:**
- The EXE will use Redis if it's available (either embedded or system-wide)
- If Redis is not available, it will fall back to in-memory storage
- Rate limits will persist between restarts when using Redis

## Configuration

The system uses several configuration files:

- `config.py`: Main configuration settings
- `scan_directories.txt`: List of directories to monitor
- `suspicious_extensions.txt`: List of suspicious file extensions
- `.env`: Environment variables (if needed)

## Usage

1. Access the web interface at http://127.0.0.1:5000
2. Configure monitored directories through the web interface
3. Real-time protection will automatically start scanning monitored folders
4. Network monitoring will detect and block suspicious traffic
5. DNS requests will be filtered through the local DNS server

## Security Features

- Real-time file scanning for malware
- Network traffic analysis for DDoS and exfiltration attempts
- DNS-based malicious domain blocking
- Machine learning-based threat detection
- File encryption for sensitive data
- Phishing detection and protection
- Automated signature updates

## System Requirements

- Windows 10 or higher
- Python 3.8 or higher
- At least 4GB RAM
- At least 1GB free disk space

## Troubleshooting

If you encounter any issues:
1. Check the antivirus.log file for error messages
2. Ensure all required dependencies are installed
3. Verify that Redis is running (if using Redis storage)
4. Check that the application has proper permissions to access monitored directories

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request