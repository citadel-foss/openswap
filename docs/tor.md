# **Tor Setup & Configuration Guide**

This guide covers:
- Installing Tor  
- Configuring Tor settings  
- Configuring the Control Port (with/without password)  
- Setting the SOCKS Port  

You do not need to set up a Hidden Service. Makerd creates its own onion address through the Control Port.

---

## **1. Installing Tor**
### **Linux (Debian/Ubuntu)**
```bash
sudo apt update
sudo apt install tor -y
```

### MacOS
```bash
brew install tor
```

---

## **2. Configuring Tor (`torrc` File)**
### **Locate & Edit `torrc`**
### Linux
```bash
sudo nano /etc/tor/torrc
```
### MacOS
```bash
nano /opt/homebrew/etc/tor/torrc
```

---

## **3. Configuring the SOCKS Proxy**
Tor acts as a **SOCKS5 Proxy** for anonymous traffic.

Add this to `torrc`:
```ini
SOCKSPort 9050
```
Now, you can route applications through `127.0.0.1:9050`.

To test it:
```bash
sudo systemctl start tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/
```
---

## **4. Configuring Control Port**
The **Control Port** allows applications to talk to Tor.
```ini
ControlPort 9051
```

### **Option 1: No Authentication (Not Recommended for Production)**
```ini
CookieAuthentication 0
```
This allows unrestricted access—use it **only for testing**.

### **Option 2: Password Authentication (Recommended)**
1. Generate a hashed password:
   ```bash
   tor --hash-password "yourpassword"
   ```
   Example output:
   ```
   16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
   ```
2. Add it to `torrc`:
   ```ini
   HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
   ```

> **Note**: OpenSwap does not support cookie authentication. It only logs in to the Control Port with a password. Use Option 2, or Option 1 for testing.




