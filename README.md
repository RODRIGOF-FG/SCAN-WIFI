# SCAN-WIFI

<br>

Script en Python utilizando la biblioteca tkinter para la interfaz de usuario y la biblioteca nmap para realizar el escaneo de puertos a direcciones IP.

<br>

**Instalaciones para la ejecucion del script**

<br>

Instalar python en kali linux

<br>

```cmd
sudo apt-get update
sudo apt-get install python3
```

<br>

instalar la biblioteca nmap

<br>

```cmd
pip install python-nmap
```
<br>

instalar la biblioteca tkinter 

<br>

```cmd
sudo apt-get install python3-tk
```

<br>

script:

<br>
```cmd
import tkinter as tk
import nmap
import socket  



def scan_subnet(subnet):
    results_text.delete(1.0, tk.END)
    for host in range(1, 255):
        ip = f"{subnet}.{host}"
        try:
            host_info = socket.gethostbyaddr(ip)
            results_text.insert(tk.END, f"Host: {ip}\n")
            results_text.insert(tk.END, f"Host Name: {host_info[0]}\n")
            results_text.insert(tk.END, f"System Type: {host_info[2]}\n\n")
        except socket.herror:
            results_text.insert(tk.END, f"Host: {ip}\n")
            results_text.insert(tk.END, "Unable to resolve host name.\n\n")

def scan_ports(ip):
    results_text.delete(1.0, tk.END)
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-F')  # Fast scan
    for host in nm.all_hosts():
        results_text.insert(tk.END, f"Host: {host}\n")
        if "tcp" in nm[host]:
            for port in nm[host]["tcp"]:
                if port == 80:
                    results_text.insert(tk.END, f"Port {port}/TCP: HTTP\n")
                elif port == 21:
                    results_text.insert(tk.END, f"Port {port}/TCP: FTP\n")
                elif port == 22:
                    results_text.insert(tk.END, f"Port {port}/TCP: SSH\n")
                else:
                    results_text.insert(tk.END, f"Port {port}/TCP: {nm[host]['tcp'][port]['name']}\n")
        else:
            results_text.insert(tk.END, f"No open ports found on host {host}\n\n")




def scan_subnet_button():
    subnet = subnet_entry.get()
    scan_subnet(subnet)


def scan_ports_button():
    ip = ip_entry.get()
    scan_ports(ip)

root = tk.Tk()
root.title("Escáner de Red")

subnet_label = tk.Label(root, text="Subred a escanear:")
subnet_label.pack()
subnet_entry = tk.Entry(root)
subnet_entry.pack()
subnet_button = tk.Button(root, text="Escanear Subred", command=scan_subnet_button)
subnet_button.pack()

ip_label = tk.Label(root, text="IP a escanear:")
ip_label.pack()
ip_entry = tk.Entry(root)
ip_entry.pack()
ports_button = tk.Button(root, text="Escanear Puertos", command=scan_ports_button)
ports_button.pack()

results_text = tk.Text(root, height=10, width=50)
results_text.pack()

root.mainloop()

```
