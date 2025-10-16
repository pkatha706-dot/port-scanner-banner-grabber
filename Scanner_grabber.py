import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 0.5
DEFAULT_WORKERS = 100
DEFAULT_OUTPUT = "scan_results.txt"


class Scanner:
    def __init__(self, ip):
        self.ip = ip
        self.open_ports = []

    def __str__(self):
        return f"Scanner: {self.ip}"

    def add_port(self, port):
        self.open_ports.append(port)

    def is_open(self, port, timeout=DEFAULT_TIMEOUT):
        try:
            with socket.create_connection((self.ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception:
            return False

    def _check_port_worker(self, port, timeout):
        if self.is_open(port, timeout=timeout):
            return port
        return None

    def scan(self, lowerport, upperport, timeout=DEFAULT_TIMEOUT, workers=DEFAULT_WORKERS):
        self.open_ports = []
        if lowerport > upperport:
            lowerport, upperport = upperport, lowerport

        ports = range(max(1, lowerport), min(65535, upperport) + 1)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self._check_port_worker, p, timeout): p for p in ports}
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res is not None:
                        self.add_port(res)
                        print(f"[+] Open port: {res}")
                except Exception:
                    pass
        self.open_ports.sort()

    def write(self, filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Open ports for {self.ip}:\n")
            for p in self.open_ports:
                f.write(f"{p}\n")


class Grabber:
    def __init__(self, ip, port, timeout=DEFAULT_TIMEOUT):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None

    def _connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.ip, self.port))
        return s

    def read(self, length=1024):
        try:
            with self._connect() as s:
                s.settimeout(self.timeout)
                try:
                    data = s.recv(length)
                    if not data:
                        return ""
                    return data.decode('utf-8', errors='replace').strip()
                except socket.timeout:
                    return ""
        except Exception as e:
            return f"<error: {e}>"

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


def grab_banner_worker(ip, port, timeout=DEFAULT_TIMEOUT):
    g = Grabber(ip, port, timeout=timeout)
    banner = g.read()
    g.close()
    return port, banner


def write_full_results(filepath, target, ip, elapsed, open_ports, banners):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Scan results for target: {target} ({ip})\n")
        f.write(f"Elapsed time: {elapsed:.2f} seconds\n")
        f.write("=" * 60 + "\n")
        if not open_ports:
            f.write("No open ports found.\n")
            return
        f.write("Open ports and banners:\n")
        for p in open_ports:
            banner = banners.get(p, "")
            banner_one_line = banner.replace("\n", "\\n")
            f.write(f"{p}\t{banner_one_line}\n")


def get_int_input(prompt, default):
    try:
        val = input(f"{prompt} [{default}]: ").strip()
        return int(val) if val else default
    except ValueError:
        print("Invalid number, using default.")
        return default


def main():

    target = input("Target IP or hostname : ").strip()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Could not resolve target. Exiting.")
        return

    start_port = get_int_input("Start port", default=1)
    end_port = get_int_input("End port",default=65535)
    timeout = float(input(f"Socket timeout in seconds [{DEFAULT_TIMEOUT}]: ").strip() or DEFAULT_TIMEOUT)
    workers = get_int_input("Concurrent worker threads", DEFAULT_WORKERS)
    output_file = input(f"Output filename [{DEFAULT_OUTPUT}]: ").strip() or DEFAULT_OUTPUT

    print(f"\nScanning {target} ({ip}) ports {start_port}-{end_port} with timeout {timeout}s using {workers} workers...")
    t0 = time.time()
    scanner = Scanner(ip)
    scanner.scan(start_port, end_port, timeout=timeout, workers=workers)
    open_ports = scanner.open_ports

    banners = {}
    if open_ports:
        print("Grabbing banners concurrently...")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(grab_banner_worker, ip, p, timeout): p for p in open_ports}
            for fut in as_completed(futures):
                try:
                    port, banner = fut.result()
                    banners[port] = banner
                    if banner:
                        preview = banner.splitlines()[0][:200]
                        print(f"[+] Banner {port}: {preview!r}")
                    else:
                        print(f"[+] Banner {port}: <empty>")
                except Exception as e:
                    p = futures.get(fut, '?')
                    banners[p] = f"<error: {e}>"

    t1 = time.time()
    elapsed = t1 - t0

    scanner.write(output_file + ".ports.txt")
    write_full_results(output_file, target, ip, elapsed, open_ports, banners)

    print(f"\nScan complete in {elapsed:.2f} seconds.")
    print(f"Port list saved to: {output_file}.ports.txt")
    print(f"Full results saved to: {output_file}")

if __name__ == "__main__":
    main()
