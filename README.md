# VRV Security Python Intern Assignment

Greetings,
This is Ravin D. It is my pleasure to showcase this assignment as part of my internship application. I hope it reflects not just my technical skills but also my practical approach to solving real-world problems with clarity and creativity.

## Code Walkthrough

The program is built around the `LogAnalyzer` class. It keeps everything organized and reusable, so we can easily add features later.

### Initializing the useful variables: `__init__`
The program starts by initializing counters to keep track of requests, endpoints, and failed logins.

```python
def __init__(self, log_file, output_file, failed_login_threshold):
    self.log_file = log_file
    self.output_file = output_file
    self.failed_login_threshold = failed_login_threshold
    self.ip_requests = Counter()
    self.endpoint_requests = Counter()
    self.failed_logins = Counter()
```

### Parsing the Logs: `parse_log_file`
This is part of the code reads the log file line by line, splits each line into parts, and extracts key details like:

- **IP address:** Who made the request?
- **Endpoint:** What did they request?
- **Status Code:** Was it successful or did something go wrong?

If a request failed (status code `401` or the message says “Invalid credentials”), it counts as a failed login attempt.
```python
def parse_log_file(self):
    with open(self.log_file, "r") as file:
        for line in file:
            parts = line.split()
            
            ip = parts[0]
            endpoint = parts[6]
            status_code = parts[8]
            message = " ".join(parts[9:]) if len(parts) > 9 else ""
            self.ip_requests[ip] += 1
            self.endpoint_requests[endpoint] += 1
            if status_code == "401" or "Invalid credentials" in message:
                self.failed_logins[ip] += 1
```

### Finding the Top Endpoint: `get_most_accessed_endpoint`
This method searches through the data and gets out the endpoint that was accessed the most.
```python
def get_most_accessed_endpoint(self):
    return self.endpoint_requests.most_common(1)[0] if self.endpoint_requests else ("None", 0)
```

### Showing Results: `display_results`

1. **Requests by IP** are listed in a neat table.
2. The **most visited endpoint** is highlighted.
3. Any **suspicious IPs** with too many failed logins are flagged.
```python
def display_results(self):
    print("\nRequests per IP:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in self.ip_requests.items():
        print(f"{ip:<20}{count:<15}")
    print("\nMost Frequently Accessed Endpoint:")
    most_accessed_endpoint = self.get_most_accessed_endpoint()
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<15}")
    for ip, count in self.failed_logins.items():
        if count > self.failed_login_threshold:
            print(f"{ip:<20}{count:<15}")
```

### Saving Results: `save_to_csv`
This method writes everything to a CSV file. The CSV includes:
1. **Requests by IP**
2. **Most accessed endpoint**
3. **Suspicious IPs with failed logins**
```python
def save_to_csv(self):
    with open(self.output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in self.ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        most_accessed_endpoint = self.get_most_accessed_endpoint()
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in self.failed_logins.items():
            if count > self.failed_login_threshold:
                writer.writerow([ip, count])
```

---

## Sample Log File Used:
This is the log file which was attached in Notion Page of VRV Security's Python Intern Assignment.
I am attaching it once again for your reference.

```bash
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312
198.51.100.23 - - [03/Dec/2024:10:12:38 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:39 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:40 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:41 +0000] "GET /dashboard HTTP/1.1" 200 1024
198.51.100.23 - - [03/Dec/2024:10:12:42 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024
203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:45 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:47 +0000] "GET /profile HTTP/1.1" 200 768
192.168.1.1 - - [03/Dec/2024:10:12:48 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:49 +0000] "POST /feedback HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:50 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.1 - - [03/Dec/2024:10:12:51 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:52 +0000] "GET /about HTTP/1.1" 200 256
203.0.113.5 - - [03/Dec/2024:10:12:53 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:54 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:55 +0000] "GET /contact HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:56 +0000] "GET /home HTTP/1.1" 200 512
192.168.1.100 - - [03/Dec/2024:10:12:57 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:58 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:59 +0000] "GET /dashboard HTTP/1.1" 200 1024
192.168.1.1 - - [03/Dec/2024:10:13:00 +0000] "GET /about HTTP/1.1" 200 256
198.51.100.23 - - [03/Dec/2024:10:13:01 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:13:02 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:13:03 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:13:04 +0000] "GET /profile HTTP/1.1" 200 768
198.51.100.23 - - [03/Dec/2024:10:13:05 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:13:06 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:13:07 +0000] "POST /feedback HTTP/1.1" 200 128
```    


## Output from Sample Log File

### Terminal
```
Requests per IP:
IP Address          Request Count
192.168.1.1         7
203.0.113.5         8
10.0.0.2            6
198.51.100.23       8
192.168.1.100       5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
IP Address          Failed Login Attempts

Results saved to log_analysis_results.csv        
```

### Output in the log_analysis_results.csv
```
Requests per IP
IP Address,Request Count
192.168.1.1,7
203.0.113.5,8
10.0.0.2,6
198.51.100.23,8
192.168.1.100,5

Most Accessed Endpoint
Endpoint,Access Count
/login,13

Suspicious Activity
IP Address,Failed Login Count

```

---

## Understanding the "Suspicious Activity Detected" Section

The "Suspicious Activity Detected" section is empty because none of the IP addresses has exceeded the `FAILED_LOGIN_THRESHOLD` of **10 failed login attempts**, as defined in the code. 

From my manual log analysis:

- **203.0.113.5**: 8 failed login attempts detected
- **192.168.1.100**: 5 failed login attempts detected

The `FAILED_LOGIN_THRESHOLD` is set to **10**, so neither IP meets the condition to be flagged as suspicious.

So, if I change the `FAILED_LOGIN_THRESHOLD` to **3** for instance, the IP meets the condition to be flagged as suspicious.

## Output from Sample Log File After changing FAILED_LOGIN_THRESHOLD to 3

### Terminal
```
Requests per IP:
IP Address          Request Count
192.168.1.1         7
203.0.113.5         8
10.0.0.2            6
198.51.100.23       8
192.168.1.100       5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
IP Address          Failed Login Attempts
203.0.113.5         8
192.168.1.100       5

Results saved to log_analysis_results.csv 
```

### Output in the log_analysis_results.csv
```
Requests per IP
IP Address,Request Count
192.168.1.1,7
203.0.113.5,8
10.0.0.2,6
198.51.100.23,8
192.168.1.100,5

Most Accessed Endpoint
Endpoint,Access Count
/login,13

Suspicious Activity
IP Address,Failed Login Count
203.0.113.5,8
192.168.1.100,5

```

Thus, it is now working as expected.


### **Conclusion**

This project has given me a great experience and through this task, I’ve been able to apply my skills to solve a real-world problem step-by-step, ensuring the solution is effective and easy to understand. I also created this **README.md** because I believe **documentation** is a crucial step in every project. It helps ensure clarity and makes the process accessible to others.
I'm grateful for the opportunity to apply for an internship with **VRV Security** and would love to contribute to your mission of creating secure digital spaces. Thank you for considering my work, and I look forward to discussing how I can contribute to your team!
