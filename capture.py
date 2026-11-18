import sys
import subprocess
import time

def capture_screenshot(url, output_path, wait_ms=3000):
    cmd = [
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        '--headless',
        '--disable-gpu',
        '--window-size=1440,900',
        f'--virtual-time-budget={wait_ms}',
        f'--screenshot={output_path}',
        url
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    print(f"Captured: {output_path} | stderr: {res.stderr.strip()}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8000/'
    out = sys.argv[2] if len(sys.argv) > 2 else 'd:\\ctf\\screenshot_current.png'
    capture_screenshot(target, out)

