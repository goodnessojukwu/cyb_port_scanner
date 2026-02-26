# Linux Local Port Scanner

## 📌 What is this program?
This program acts like a security guard for your Linux computer. It checks all the "doors" (network ports) on your system to see which ones are open and waiting for connections. 

Instead of sending network packets over the internet to scan for open ports (like a hacker tool would do), this program simply looks at the internal records of your own computer to find out exactly what is happening. It lists every open TCP and UDP port, and tells you the exact name of the program (the process) that opened it.

## 🧠 How It Works in Detail (The /proc Filesystem)
In Linux, there is a saying: "Everything is a file." Even running programs and network connections are treated as files inside a special hidden folder called `/proc`.


Because we chose **Option C** for this assignment, our program does not use external cheat tools like `netstat`. Instead, it does the hard work itself by reading these special `/proc` files in three main steps:

### Step 1: Finding the Open Ports
The program opens the files `/proc/net/tcp` and `/proc/net/udp`. The Linux kernel updates these files constantly with a list of active network connections. 
Our code reads this file line by line to find:
* **The IP Address:** (e.g., is it listening only to the local computer, or the whole internet?)
* **The Port Number:** (e.g., port 80 or 22)
* **The Inode:** This is a very important, unique ID number assigned to the open port.

### Step 2: Finding the Program
Now we have an open port and the inode, but we don't know which program owns it. 
To find out, our program looks at every single running process on the computer. Inside the `/proc` folder, every running program has its own folder named after its Process ID (PID), like `/proc/1234/`. 

Inside that folder is another folder called `fd` (File Descriptors). This lists all the files and connections that program is currently holding.

Our code checks every file descriptor to see if it matches the inode we found in Step 1. When it finds a match, we know exactly which Process ID owns the port!

### Step 3: Translating Numbers to Names
Once we have the Process ID, we read a file called `/proc/[PID]/comm` to get the actual human-readable name of the program (like `firefox` or `sshd`). We also use a built-in C function called `getservbyport` to translate the port number into a known service name (for example, translating port 22 to `ssh`).

## 🚀 Special Features
Aside from the basic requirements, this program includes some advanced bonus features:
* **Risk Labels:** It looks at the IP address the port is attached to. If it is attached to `127.0.0.1`, it labels it **"Local-only"** (safe). If it is attached to `0.0.0.0`, it labels it **"Exposed"** (anyone on the network can try to connect).
* **High-Risk Flags:** It checks the port against a list of commonly hacked ports (like 22, 80, 443, 3389). If it matches, it prints a bold `[HIGH RISK]` warning next to it.
* **Text File Report:** It prints a neat table on your screen, but it also saves an exact copy of that table to a file named `ports_report.txt` for your records.

## 📂 How the Code is Organized
To keep things clean, the code is split into several smaller files, rather than one massive, messy file:
* `port_scanner.h`: The "table of contents" that links all the files together.
* `main.c`: The central hub that starts the program and prints the tables.
* `parse_proc_net.c`: The code for Step 1 (finding the ports and inodes).
* `find_process_by_inode.c`: The code for Step 2 (matching the inode to a program).
* `check_high_interest.c` & `set_risk_label.c`: The code for our advanced security features.
* `Makefile`: A set of instructions that tells the computer how to compile all these files together into one final program.

## 🛠️ How to Compile and Run

**1. Build the program**
Open your terminal in the folder with your files and type:
```bash
make
(This automatically safely compiles all the .c files using strict warning flags to ensure there are no bugs).

**2. Run the program**
You must run this program as an administrator (root). Why? Because regular users are not allowed to look inside the /proc folders of other users' programs. If you don't use sudo, the program will still find the ports, but it will say "Deny" for the process names.
