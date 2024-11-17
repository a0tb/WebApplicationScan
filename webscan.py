import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()
# pivot
# Proxy configuration
PROXIES = {
    "http": "socks5h://127.0.0.1:1080",
    "https": "socks5h://127.0.0.1:1080"
}

# Define subnets and ports to scan
subnets = [
    "192.168.50.0/23",
    "192.168.49.1/24",
]
ports = [80, 443, 8080, 8443, 8000, 8888]

def fetch_title_with_proxy(ip, port):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"
    try:
        response = requests.get(url, proxies=PROXIES, timeout=5, verify=False)
        title = None
        if "<title>" in response.text:
            title = response.text.split("<title>")[1].split("</title>")[0].strip()
        return {"ip": ip, "port": port, "status": response.status_code, "title": title if title else "None"}
    except requests.RequestException:
        return None

# Scan a single IP for open web ports
def scan_ip(ip, progress_task, progress):
    results = []
    for port in ports:
        result = fetch_title_with_proxy(ip, port)
        if result:
            results.append(result)
        progress.update(progress_task, advance=1)
    return results

# Scan all subnets
def scan_subnets():
    results = []
    total_tasks = sum(len(list(ip_network(subnet).hosts())) * len(ports) for subnet in subnets)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        scan_task = progress.add_task("Scanning Subnets...", total=total_tasks)
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for subnet in subnets:
                console.log(f"Scanning subnet: {subnet}")
                for ip in ip_network(subnet).hosts():
                    futures.append(executor.submit(scan_ip, str(ip), scan_task, progress))
            
            for future in as_completed(futures):
                results.extend(future.result() or [])
    return results

if __name__ == "__main__":
    from pprint import pprint

    requests.packages.urllib3.disable_warnings()

    # Start scanning
    console.log("Starting scan...")
    scan_results = scan_subnets()

    table = Table(title="Web Application Scan Results")
    table.add_column("IP Address", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Title", style="yellow")

    for result in scan_results:
        table.add_row(result["ip"], str(result["port"]), str(result["status"]), result["title"])

    console.print(table)

    with open("web_scan_results.txt", "w") as f:
        for result in scan_results:
            f.write(f"{result['ip']}:{result['port']} - Status: {result['status']}, Title: {result['title']}\n")
