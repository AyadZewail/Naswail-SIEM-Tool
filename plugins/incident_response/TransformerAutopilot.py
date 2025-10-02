from sentence_transformers import SentenceTransformer, util
from abc import ABC, abstractmethod
# from core.interfaces import IAutopilotEngine

class IAutopilotEngine(ABC):
    @abstractmethod
    def decide(self, prompt: str, ip: str, port: str) -> dict:
        """
        Should return a dict like:
        {
            "action": "block_ip",
            "params": ["1.2.3.4"]
        }
        """
        pass

class TransformerAutopilot(IAutopilotEngine):
    def __init__(self):
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.functions = {
            "block_ip": ["Provide attacking IP addresses to your ISP. They can implement restrictions to prevent further traffic.",
                            "Set up alerts whenever you encounter login attempts from anomalous IP addresses and make sure to block them.",
                            "A common way to restrict login attempts is to temporarily ban an IP from logging in after five failed login attempts.",
                            "The simplest defense against a DoS attack is either allowing only legitimate IP addresses or blocking ones from known attackers.",
                            "If you have identified domains or IP addresses that are known to be leveraged by threat actors for command and control, issue threat mitigation requests to block the communication from",
                            "block suspicious IP addresses in real-time",
                            "update the firewall settings to block a malicious IP.",
                            "blocking malicious IP addresses",
                            "IP blacklisting is a method used to filter out illegitimate or malicious IP addresses from accessing your networks.",
                            "Blocking malicious IP addresses is a critical yet complex task.",
                            "Blocking an IP address can improve your security and give you peace of mind.",
                            "Blocking malicious IP addresses can help protect a website from various types of cyberattacks such as Denial of Service (DoS) attacks, etc.",
                            "Blocking particular IP addresses helps stop unauthorized access.",
                            "IP restriction works by blocking traffic from a particular IP address. It prevents unwanted or harmful traffic from reaching your website or network.",
                            "Blocking unwanted IP addresses stops unauthorized users from accessing sensitive systems and data.",
                            "IP addresses are blocked for multiple reasons, including to protect networks against attacks.",
                            "You can block IP addresses to defend your website from external attacks, including those that might steal your data.",
                            "it's worth considering action with IP address blocking.",
                            "Organizations may need assistance from their ISP in blocking a major network-based attack or tracing its origin.",
                            "Configure firewalls to block, as a minimum, inbound traffic sourced from IP addresses that are reserved",
                            "Firewalls can be adjusted to deny incoming traffic from attackers based on protocols, ports, or originating IP addresses.",
                            "IP address blocking is commonly used to protect against brute force attacks and to prevent access by a disruptive address.",
                            "If you detect a malicious IP address, block it immediately using firewalls or antivirus software.",
                            "Businesses can protect against malicious IPs by implementing firewalls and IP blocking.",
                            "Take appropriate mitigations to block or closely monitor inbound and outbound traffic from known Tor nodes.",
                            "Filter network traffic to only allow IP addresses that are known to need access.",
                            "The best way to prevent IPs from entering your network is to block an IP address from the router level.",
                            "Use IP addresses and Address objects in a Security Policy to block traffic from known bad sources.",
                            "Blocking a Destination IP address can block connections to a malicious IP address.",
                            "Block a remote malicious IP by blocking outgoing communications.",
                            "Block an external IP address that is attacking the corporate network by blocking incoming communications.",
                            "Block traffic to and from IP addresses identified as malicious by trusted sources.",
                            "Create a network security rule to block outgoing traffic to malicious IP addresses.",
                            "Network protection can block access to malicious IPs or domains.",
                            "Update the Network Firewall rule group to block traffic to malicious IP addresses.",
                            "Use a network ACL to block specific IP addresses from accessing.",
                            "Mitigate the risk of data breaches by blocking IP addresses associated with known threat actors.",
                            "Enhance your network security by implementing IP blacklisting to prevent access from malicious sources.",
                            "In response to a cyber attack, promptly block the offending IP addresses to halt further intrusion attempts.",
                            "Protect your web applications from brute force attacks by temporarily banning IP addresses after multiple failed login attempts.",
                            "Strengthen your defense against botnets by blocking IP addresses identified as command and control servers.",
                            "Collaborate with your internet service provider to block traffic from IP addresses involved in large-scale DDoS attacks.",
                            "Regularly update your firewall rules to block newly identified malicious IP addresses.",
                            "Use threat intelligence feeds to dynamically block IP addresses associated with cyber threats.",
                            "Prevent lateral movement within your network by blocking internal IP addresses that exhibit suspicious behavior.",
                            "Ensure compliance with security policies by blocking IP addresses that violate access controls.",
                            "Safeguard your organization's assets by implementing IP blocking as part of your incident response plan.",
                            "Reduce the impact of denial-of-service attacks by filtering out traffic from known malicious IP addresses.",
                            "Enhance your security posture by blocking IP addresses flagged by security information and event management (SIEM) systems.",
                            "Defend against phishing campaigns by blocking IP addresses that host malicious websites.",
                            "Protect your email infrastructure by blocking IP addresses used in spam campaigns.",
                            "Strengthen your cloud security by configuring security groups to block traffic from unauthorized IP addresses.",
                            "Prevent data exfiltration by blocking outbound connections to known malicious IP addresses.",
                            "Mitigate the spread of malware by blocking IP addresses used for command and control communications.",
                            "Enhance your zero-trust architecture by restricting access based on IP addresses.",
                            "Improve your network resilience by blocking IP addresses involved in reconnaissance activities.",
                            "Protect your IoT devices by blocking IP addresses that attempt to exploit known vulnerabilities.",
                            "Enhance your mobile security by blocking IP addresses that distribute malware through app stores.",
                            "Strengthen your supply chain security by blocking IP addresses from untrusted vendors.",
                            "Protect your financial transactions by blocking IP addresses associated with fraudulent activities.",
                            "Enhance your customer data protection by blocking IP addresses that attempt to scrape sensitive information.",
                            "Mitigate insider threats by monitoring and blocking anomalous internal IP addresses.",
                            "Protect your intellectual property by blocking IP addresses that attempt to access restricted resources.",
                            "Enhance your compliance with data protection regulations by blocking IP addresses from regions with strict data access controls.",
                            "Strengthen your defense against advanced persistent threats (APTs) by blocking IP addresses used in multi-stage attacks.",
                            "Protect your critical infrastructure by blocking IP addresses involved in nation-state cyber attacks.",
                            "Enhance your security information and event management (SIEM) capabilities by correlating alerts with IP blocking actions.",
                            "Mitigate the risk of ransomware by blocking IP addresses that distribute ransomware payloads.",
                            "Protect your virtual private network (VPN) by blocking IP addresses that attempt to brute-force VPN credentials.",
                            "Enhance your web application firewall (WAF) effectiveness by blocking IP addresses that trigger multiple security rules.",
                            "Strengthen your endpoint security by blocking IP addresses that deliver malware through exploit kits.",
                            "Protect your database servers by blocking IP addresses that attempt SQL injection attacks.",
                            "Enhance your network segmentation by blocking lateral movement between different IP address ranges.",
                            "Mitigate the impact of zero-day exploits by blocking IP addresses known to exploit new vulnerabilities.",
                            "Protect your software development lifecycle by blocking IP addresses that attempt to compromise source code repositories.",
                            "Enhance your security operations center (SOC) efficiency by automating IP blocking based on threat intelligence.",
                            "Mitigate the risk of account takeovers by blocking IP addresses with a history of malicious login attempts.",
                            "Protect your customer accounts by implementing IP blocking for login attempts.",
                            "Enhance your fraud detection by blocking IP addresses associated with known fraudsters.",
                            "Strengthen your e-commerce security by blocking IP addresses that engage in web scraping or carding activities.",
                            ],
            "block_port": ["install the latest updates", "regularly patch vulnerabilities"],
            "limit_rate": ["Implementing rate limiting to restrict the number of requests from specific IP addresses or sources within a given timeframe can be effective.",
                            "Rate limiting mitigates DDoS threats by preventing any given traffic source from sending too many requests.",
                            "Rate limiting helps mitigate bot attacks including DDoS attacks.",
                            "Limit the number of login attempts to reduce a hacker’s chances of guessing credentials.",
                            "rate limiting blocks systematic submission of randomly generated credentials.",
                            "Rate limiting can be used to limit login attempts, for example, allowing only 3 or 4 attempts per hour from a single IP address, to block bots from guessing passwords.",
                            "implement a rate-limiting mechanism that effectively limits the number of failed authentication attempts for memorized secrets.",
                            "Rate limiting controls the number of requests a single IP or user agent can make within a specific timeframe, slowing down scrapers and protecting server resources.",
                            "Implement rate limiting by allowing only a few searches per second from any specific IP address or user to prevent scraping.",
                            "In the case of data scraping, rate limiting detects and blocks scraper bots from copying large amounts of data.",
                            "Rate limiting controls the number of requests within a time frame to prevent resource overuse and mitigate DDoS and brute force attacks.",
                            "Rate limiting identifies and blocks bots submitting stolen credentials into login forms, mitigating credential stuffing attacks.",
                            "By blocking systematic submission of randomly generated credentials, rate limiting saves system resources during brute force attacks.",
                            "Rate limiting detects and blocks scraper bots, preventing them from copying large amounts of data.",
                            "Rate limiting protects against API overuse by limiting the number of API calls per hour or day.",
                            "By limiting login attempts to 3 or 4 per hour from a single IP address, rate limiting blocks bots from guessing passwords.",
                            "Rate limiting can be used to set a threshold on the number of connection requests, preventing systems from being overwhelmed by SYN flood attacks.",
                            "Modern networking equipment often comes with built-in rate-limiting capabilities to limit the number of SYN requests from a single IP address within a certain time frame.",
                            "Rate limiting is a security mechanism that controls and restricts the number of requests or actions a user or IP address can perform within a specific time frame.",
                            "IP-based rate limiting limits the number of requests from a single IP address, helping to mitigate DDoS and brute-force attacks.",
                            "Rate limiting is an essential process that limits the amount of requests a client can send to the server to mitigate attacks like DoS, brute force, and enumeration.",
                            "Implementing targeted rate limiting can reduce requests on specific endpoints, for example, allowing only 5 connection attempts to prevent brute force attacks.",
                            "Rate limiting helps prevent a user from exhausting the system’s resources by controlling the number of API calls within a set time frame.",
                            "Without rate limiting, it’s easier for a malicious party to overwhelm the system with requests, thereby consuming memory, storage, and network capacity.",
                            "Rate limiting is another technique to mitigating DDoS attacks that involves implementing restrictions on the number of requests a server can accept a specific IP address within a specific time frame.",
                            "By implementing strict rate limits, you can mitigate the impact of a DDoS attack. Even if the attackers control a large number of machines, each individual client will be restricted in how many requests it can send.",
                            "Rate limiting can be a productive method for preventing DDoS attacks. It works by limiting the number of requests a user (or bot) can make to a service or server in a time period, preventing them from flooding systems and rendering them unavailable.",
                            "Rate limiting is a critical defense mechanism, especially against Distributed Denial of Service (DDoS) and brute force attacks.",
                            "Effective mitigation to prevent DDoS attacks often involves a combination of traffic analysis, rate limiting, and filtering to distinguish between legitimate user traffic and malicious attack traffic, allowing the service to remain available to the former while blocking the latter.",
                            "One of the most common use cases for rate limiting is to block brute force attacks.",
                            "Implementing robust rate-limiting measures is essential for web applications to prevent brute force attacks and potential service overload.",
                            "Rate limiting is simply configuring our environment to reject requests that come in too rapidly from a certain source.",
                            "All these attacks can be mitigated by implementing an essential process that limits the amount of requests a client can send to the server: rate limiting.",
                            "Rate limiting blocks these attacks to save system resources.",
                            "Limiting the number of requests that a user can perform can drastically slow a web scraper's performance without harming real users.",
                            "Rate limiting is a technique used to prevent a large amount of requests from being sent from one user.",
                            "We can build protections against web scraping into our application, such as rate limiting.",
                            "Rate limiting is often employed to stop bad bots from negatively impacting a website or application.",
                            "Rate limiting helps to prevent the overloading of servers by limiting the number of requests that can be made in a given time frame, thus avoiding resource starvation due to a Denial of Service (DoS) attack.",
                            "Rate limiting is used to prevent Denial-of-Service (DoS) attacks.",
                            "Rate limiting involves setting a threshold on the number of connection requests a system will accept within a given time frame to prevent SYN flood attacks.",
                            "Rate limiting intentionally limits the number of requests a server receives from each individual IP address over a certain amount of time to prevent SYN flood attacks.",
                            "Modern networking equipment often comes with built-in rate-limiting capabilities to limit the number of SYN requests from a single IP address, helping prevent SYN Flood attacks.",
                            "Rate limiting limits the number of SYN requests that can be sent to a server at any one time to mitigate SYN flood attacks.",
                            "Mitigation should focus on using Response Rate Limiting to restrict the amount of traffic for authoritative servers in DNS amplification attacks.",
                            "implement a rate-limiting mechanism that effectively limits the number of failed authentication attempts that can be made on the subscriber’s account.",
                            "Limiting bandwidth helps with attacks",
                            "limit the number of incoming requests",
                            "rate limiting sets a maximum threshold on the number of requests that can be processed per second",
                            "rate-limiting incoming connection requests is a crucial strategy to prevent attacks",
                            "Use Response Rate Limiting to restrict the amount of traffic",
                            "restricting the number of incoming requests from a given IP address may prevent attacks",
                            "Rate limit bad password guesses to a fixed number in a given time period",
                            ]
        }

    def decide(self, mitgation_sentence):
        mit_vec = self.model.encode(mitgation_sentence, convert_to_tensor=True)

        best_score = -1.0
        best_func = None

        for func_name, descriptions in self.functions.items():
            desc_vecs = self.model.encode(descriptions, convert_to_tensor=True)
            scores = util.cos_sim(mit_vec, desc_vecs)

            top_score = scores.max().item()

            if top_score > best_score:
                best_score = top_score
                best_func = func_name

        return best_func, ""
    

# if __name__ == "__main__":
#     ta = TransformerAutopilot()
#     prompt = "Now, in some cases we want to control the rate of the incoming traffic, from certain IP addresses"
#     function, log = ta.decide(prompt)
#     print(function)
#     print(log)