import csv
from collections import Counter

# Constant Variables
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10


class LogAnalyzer:
    
    def __init__(self, log_file, output_file, failed_login_threshold):
        self.log_file = log_file
        self.output_file = output_file
        self.failed_login_threshold = failed_login_threshold
        self.ip_requests = Counter()
        self.endpoint_requests = Counter()
        self.failed_logins = Counter()

    def parse_log_file(self): # Read the log file and extract data for analysis
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

    def get_most_accessed_endpoint(self): # Return the most accessed endpoint, or a default if no data is available
        return self.endpoint_requests.most_common(1)[0] if self.endpoint_requests else ("None", 0)

    def save_to_csv(self): # Write analysis results to a CSV file
        with open(self.output_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in self.ip_requests.items():
                writer.writerow([ip, count])

            # Most accessed endpoint
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            most_accessed_endpoint = self.get_most_accessed_endpoint()
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

            # Suspicious activity
            writer.writerow([])
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in self.failed_logins.items():
                if count > self.failed_login_threshold:
                    writer.writerow([ip, count])

    def display_results(self): # Print results to the console for review
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


if __name__ == "__main__":
    
    analyzer = LogAnalyzer(LOG_FILE, OUTPUT_CSV, FAILED_LOGIN_THRESHOLD)
    analyzer.parse_log_file()
    analyzer.display_results()
    analyzer.save_to_csv()
    print(f"\nResults saved to {OUTPUT_CSV}")
