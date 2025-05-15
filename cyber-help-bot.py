import re
import random
from datetime import datetime

class CyberSecurityChatbot:
    def __init__(self):
        self.name = "CyberGuard"
        self.version = "2.0"
        self.knowledge_base = self._initialize_knowledge_base()
        self.greetings = ["hi", "hello", "hey", "greetings"]
        self.goodbyes = ["bye", "goodbye", "exit", "quit"]
        
    def _initialize_knowledge_base(self):
        return {
            "phishing": {
                "question": r"(what is phishing|how to spot phishing|phishing emails?)",
                "answer": [
                    "Phishing is a cyber attack where criminals impersonate legitimate organizations to steal sensitive data. These attacks often come via email, text, or fake websites designed to look authentic. Common targets include login credentials, credit card numbers, and personal information. Always verify unexpected requests for information through official channels. Look for subtle misspellings in email addresses and suspicious links.",
                    "To identify phishing attempts, examine sender addresses carefully - they often mimic real addresses with slight alterations. Be wary of messages creating urgency ('Your account will be closed!') or offering too-good-to-be-true rewards. Hover over links to see the actual URL before clicking. Legitimate organizations won't ask for sensitive information via email. When in doubt, contact the company directly through their official website.",
                    "Phishing emails typically contain grammatical errors, generic greetings ('Dear Customer'), and spoofed sender addresses. They may include malicious attachments or links to fake login pages. Some sophisticated attacks (spear phishing) target specific individuals with personalized messages. Always enable multi-factor authentication as an extra security layer. Remember that banks and government agencies never request sensitive data via email."
                ]
            },
            "malware": {
                "question": r"(what is malware|types of malware|malware protection?)",
                "answer": [
                    "Malware is malicious software designed to damage systems or steal data. It includes viruses that replicate themselves, worms that spread through networks, and trojans disguised as legitimate software. Ransomware encrypts files for extortion, while spyware secretly monitors user activity. Rootkits hide deep in systems, and adware displays unwanted advertisements. All forms can cause significant harm to individuals and organizations.",
                    "Protecting against malware requires multiple layers of defense. Always use reputable antivirus software and keep it updated. Be cautious with email attachments and downloads from untrusted sources. Regularly update operating systems and applications to patch vulnerabilities. Enable firewalls and consider using application whitelisting. Educate yourself about common infection methods to avoid falling victim to malware attacks.",
                    "Different malware types pose unique threats: Viruses attach to clean files and spread, worms exploit network vulnerabilities, trojans trick users into installing them. Spyware tracks keystrokes and browsing habits, while ransomware locks critical files. Adware slows systems with pop-ups, and rootkits provide backdoor access. Some malware combines multiple types for maximum damage. Regular backups and system scans are essential for detection and recovery."
                ]
            },
            "password": {
                "question": r"(strong password|password best practices|create secure password?)",
                "answer": [
                    "Creating strong passwords is crucial for online security. A good password should be at least 12 characters long with uppercase, lowercase, numbers, and symbols. Avoid dictionary words, names, or personal information. Consider using passphrases - memorable sentences like 'MyDogAte3Pizzas@Noon!' are both strong and easier to remember. Never reuse passwords across different accounts, as this creates a single point of failure.",
                    "Password managers help generate and store complex, unique passwords for all accounts. Enable two-factor authentication wherever possible for added security. Change passwords immediately if a service reports a breach. Be wary of security questions - answers should be as secure as passwords. Avoid writing passwords down, but if necessary, keep them in a locked location separate from your devices.",
                    "Modern password cracking tools can guess weak passwords in seconds. Dictionary attacks try common words, while brute force attempts all combinations. Rainbow tables reverse-engineer hashed passwords. To counter these, use unpredictable combinations without personal meaning. Password managers can create and remember strong passwords for you. Biometric authentication (fingerprint/face ID) provides convenient additional protection when available."
                ]
            },
            "ransomware": {
                "question": r"(what is ransomware|prevent ransomware|ransomware attack?)",
                "answer": [
                    "Ransomware is malicious software that encrypts files and demands payment for decryption. Attacks often start through phishing emails or exploiting unpatched vulnerabilities. Payment doesn't guarantee file recovery and funds criminal operations. Hospitals, schools, and businesses are frequent targets due to their need for immediate data access. Some ransomware also steals data before encryption, threatening to release it publicly (double extortion).",
                    "Preventing ransomware requires proactive measures: Maintain regular offline backups of critical data. Keep all software updated with security patches. Use endpoint protection with ransomware detection. Train employees to recognize phishing attempts. Restrict user permissions to only necessary functions. Segment networks to limit spread. Disable macro scripts in office files. Consider disabling RDP if not needed. These steps significantly reduce infection risks.",
                    "If hit by ransomware: Immediately isolate infected systems to prevent spread. Don't pay the ransom - there's no guarantee of recovery and it encourages more attacks. Report to law enforcement (FBI, local authorities). Restore systems from clean backups after eliminating the infection. Investigate how the breach occurred to prevent recurrence. Some security firms offer free decryption tools for certain ransomware strains. Post-incident, review and strengthen all security measures."
                ]
            },
            "firewall": {
                "question": r"(what is firewall|how firewall works|types of firewall?)",
                "answer": [
                    "A firewall acts as a gatekeeper between your network and the internet, controlling incoming/outgoing traffic. It examines data packets using predefined security rules to block malicious traffic. Firewalls can be hardware appliances, software programs, or cloud-based services. They're essential for preventing unauthorized access and stopping many cyber attacks. Modern firewalls also inspect packet contents, not just headers, for deeper protection.",
                    "Firewalls operate at different network layers: Packet filters examine IP addresses and ports. Stateful inspection tracks active connections for context. Application-layer firewalls understand specific protocols like HTTP. Next-generation firewalls (NGFW) combine these with intrusion prevention and deep packet inspection. Cloud firewalls protect web applications, while personal firewalls secure individual devices. Proper configuration is crucial - overly permissive rules undermine protection.",
                    "Choosing firewall type depends on needs: Small offices might use unified threat management (UTM) appliances. Enterprises often deploy NGFWs with advanced threat detection. Web application firewalls (WAF) protect servers from HTTP exploits. Host-based firewalls secure individual computers. Virtual firewalls protect cloud environments. All should be regularly updated and monitored. Firewall logs provide valuable security insights when properly analyzed for suspicious activity."
                ]
            },
            "vpn": {
                "question": r"(what is vpn|vpn benefits|how vpn works?)",
                "answer": [
                    "A VPN (Virtual Private Network) creates an encrypted tunnel for your internet traffic, protecting data from interception. It masks your IP address, making online actions harder to trace. VPNs are essential when using public WiFi to prevent eavesdropping. They also bypass geographic restrictions by making it appear you're browsing from another location. However, not all VPNs are equal - free services may log and sell your data.",
                    "VPNs work by routing your connection through remote servers operated by the VPN provider. Your data is encrypted before leaving your device, remaining secure in transit. The VPN server decrypts the data and sends it to the intended destination. Returning traffic follows the reverse path. This process hides your actual location and protects against man-in-the-middle attacks. Modern VPNs use protocols like OpenVPN, WireGuard, or IKEv2 for optimal security and speed.",
                    "When choosing a VPN, consider: No-logs policy (verified by independent audit), strong encryption standards (AES-256), server locations, connection speed, and device compatibility. Avoid free VPNs that may compromise privacy. Corporate VPNs allow secure remote access to company resources. Some countries restrict or ban VPN usage, so check local laws. Remember that VPNs protect data in transit but don't make you anonymous - other tracking methods still exist."
                ]
            },
            "2fa": {
                "question": r"(what is two factor authentication|how 2fa works|benefits of 2fa?)",
                "answer": [
                    "Two-factor authentication (2FA) adds an extra verification step beyond just passwords. It requires something you know (password) plus something you have (phone, security key) or are (biometric). Even if hackers steal your password, they can't access accounts without the second factor. 2FA blocks 99.9% of automated attacks according to Microsoft. It's now considered essential security practice for all important accounts.",
                    "2FA methods vary: SMS codes (least secure but better than nothing), authenticator apps (Google/Microsoft Authenticator), hardware security keys (most secure), and biometrics. Push notifications to registered devices provide convenient verification. Backup codes should be stored securely for when primary methods aren't available. Some services offer 'remember this device' options to reduce 2FA prompts on trusted computers.",
                    "Implementing 2FA significantly improves account security. Start with email and financial accounts, then social media. Authenticator apps are preferable to SMS due to SIM-swapping risks. Security keys like YubiKey provide phishing-resistant protection. Enterprise 2FA systems often integrate with single sign-on (SSO) solutions. While slightly less convenient than passwords alone, the security benefits far outweigh the minor inconvenience for valuable accounts."
                ]
            },
            "social engineering": {
                "question": r"(what is social engineering|types of social engineering|prevent social engineering?)",
                "answer": [
                    "Social engineering manipulates human psychology rather than exploiting technical vulnerabilities. Attackers impersonate trusted entities to trick victims into revealing secrets or granting access. These scams often create false urgency ('Your account is compromised!') or appeal to helpfulness ('I'm from IT - need your password'). Even tech-savvy people can fall victim to sophisticated social engineering tactics that bypass technical defenses.",
                    "Common social engineering types include: Phishing (fraudulent emails), vishing (phone scams), smishing (text messages), and pretexting (fabricated scenarios). Baiting offers fake rewards, quid pro quo promises mutual benefit, while tailgating exploits physical access. CEO fraud targets employees with fake executive requests. Water holing compromises websites frequented by targets. All rely on human trust rather than software flaws.",
                    "Defending against social engineering requires awareness and skepticism. Verify unusual requests through secondary channels - call back using official numbers. Never share passwords or sensitive data in response to unsolicited contacts. Be wary of urgency pressures or too-good-to-be-true offers. Organizations should conduct regular security training and simulated phishing tests. Implement procedures for verifying sensitive requests, especially financial transactions."
                ]
            },
            "ddos": {
                "question": r"(what is ddos attack|how to prevent ddos|types of ddos?)",
                "answer": [
                    "DDoS (Distributed Denial of Service) attacks overwhelm targets with traffic from multiple sources, making services unavailable. Attackers often hijack IoT devices or servers to form botnets. Volumetric attacks flood bandwidth, while protocol attacks exhaust server resources. Application-layer attacks target specific web functions. Some last minutes, others continue for days, causing significant financial and reputational damage. Even major companies struggle with large-scale DDoS.",
                    "Preventing DDoS requires preparation: Use cloud-based DDoS protection services that can absorb massive traffic. Configure network hardware to rate-limit connections and filter malicious packets. Maintain excess bandwidth to handle surges. Distribute services across multiple locations. Hide origin server IPs behind CDNs. Monitor traffic for unusual patterns. Have an incident response plan ready. Smaller attacks might be mitigated with proper firewall and router configurations.",
                    "Different DDoS attacks require specific defenses: SYN floods need TCP stack hardening. HTTP floods require web application firewalls. DNS amplification attacks need recursive DNS server locking. Memcached attacks demand UDP port 11211 closure. Regular vulnerability scans help secure potential botnet recruits. ISPs may provide basic DDoS mitigation. For critical services, consider specialized DDoS protection providers with scrubbing centers that filter attack traffic."
                ]
            },
            "iot security": {
                "question": r"(iot security|secure smart devices|internet of things risks?)",
                "answer": [
                    "IoT security protects internet-connected devices like cameras, thermostats, and appliances from cyber threats. Many IoT devices have weak default passwords, unencrypted communications, and no update mechanisms. Compromised devices can become botnet recruits or entry points to home networks. The Mirai botnet demonstrated how vulnerable IoT can cause widespread internet disruption. Security is often an afterthought in cheap IoT products.",
                    "Securing IoT devices starts with changing default credentials to strong, unique passwords. Disable unnecessary features and remote access if not needed. Segment IoT devices onto separate network zones from computers and phones. Regularly check for and install firmware updates. Choose devices from reputable manufacturers with good security track records. Monitor network traffic for suspicious device communications. Consider IoT-specific security solutions.",
                    "Major IoT risks include: Weak authentication allowing easy takeover, unpatched vulnerabilities, insecure data storage/transmission, and lack of device management. Some devices secretly phone home to foreign servers. Physical security matters too - tampering can compromise devices. Privacy concerns arise from always-on microphones and cameras. Before purchasing, research the manufacturer's security practices and whether the device has been involved in past breaches."
                ]
            },
            "zero trust": {
                "question": r"(what is zero trust|zero trust principles|implement zero trust?)",
                "answer": [
                    "Zero Trust is a security model assuming no user or device should be trusted by default, even inside the network perimeter. It requires continuous verification of all access attempts. This approach minimizes damage from breaches by limiting lateral movement. Traditional 'trust but verify' models fail against modern threats where insiders and compromised credentials often facilitate attacks. Zero Trust is now mandated for US federal agencies.",
                    "Zero Trust operates on three principles: 'Verify explicitly' - authenticate and authorize every access request. 'Use least privilege' - grant minimum necessary access. 'Assume breach' - design systems to limit blast radius. It incorporates micro-segmentation, multi-factor authentication, and continuous monitoring. Implementation requires identity verification, device health checks, and context-aware access policies for all resources.",
                    "Implementing Zero Trust starts with identifying critical data and services. Map how data flows through your organization. Establish strong identity verification for all users and devices. Segment networks to restrict unnecessary access. Monitor and log all access attempts. Apply policies based on user, device, location, and other context. Start with pilot projects before organization-wide rollout. Tools like identity-aware proxies and software-defined perimeters help implement Zero Trust architectures."
                ]
            },
            "encryption": {
                "question": r"(what is encryption|types of encryption|how encryption works?)",
                "answer": [
                    "Encryption transforms readable data (plaintext) into scrambled ciphertext using algorithms and keys. Only authorized parties with the correct key can decrypt and read the information. Modern encryption protects data at rest (storage), in transit (networks), and in use (memory). Strong encryption is mathematically secure against brute force attacks. It's fundamental for privacy, secure communications, and data protection compliance.",
                    "Symmetric encryption (AES) uses one key for both encryption and decryption - fast but requires secure key exchange. Asymmetric encryption (RSA) uses public/private key pairs - slower but solves key distribution. Hashing (SHA-256) creates fixed-length fingerprints for data verification. End-to-end encryption ensures only communicating users can read messages. Different algorithms suit different needs based on security requirements and performance constraints.",
                    "Encryption works through complex mathematical operations that are easy to perform with the key but extremely hard to reverse without it. AES-256, the gold standard, uses multiple rounds of substitution and permutation. RSA relies on the difficulty of factoring large prime numbers. Elliptic curve cryptography provides strong security with smaller keys. Quantum computing threatens some algorithms, prompting development of post-quantum cryptography standards."
                ]
            },
            "dark web": {
                "question": r"(what is dark web|dark web vs deep web|access dark web safely?)",
                "answer": [
                    "The dark web is a small portion of the internet requiring special software (Tor) to access, offering anonymity through encrypted layers. While providing privacy for whistleblowers, it also hosts illegal marketplaces and content. The deep web refers to all unindexed content (databases, private networks) - much larger than the surface web we use daily. Most deep web content is legal, like medical records or academic databases.",
                    "Accessing the dark web carries risks: Many sites host illegal content or scams. Law enforcement monitors certain areas. Malware and exploitation attempts are common. If accessing for legitimate reasons, use Tor Browser with strict security settings. Never download files or enable plugins. Consider running Tor in a virtual machine. Use a VPN for additional privacy (though some argue this creates a single point of failure).",
                    "Dark web sites use .onion addresses and don't appear in search engines. The Tor network routes traffic through multiple encrypted nodes worldwide. While providing anonymity, timing analysis and other techniques can sometimes de-anonymize users. Journalists and activists use it to bypass censorship, but criminals exploit its privacy features. Always consider legal and ethical implications before exploring the dark web."
                ]
            },
            "cyber insurance": {
                "question": r"(what is cyber insurance|cyber insurance coverage|need cyber insurance?)",
                "answer": [
                    "Cyber insurance covers financial losses from data breaches, cyber attacks, and related incidents. Policies typically include breach response costs, legal fees, regulatory fines, and customer notifications. Some cover business interruption losses and ransomware payments (though this is controversial). Premiums depend on your security posture - better defenses mean lower rates. It's not a substitute for security but helps manage residual risk.",
                    "Cyber insurance coverage varies: First-party covers direct losses like data recovery and reputational harm. Third-party covers claims from affected customers or partners. Some exclude certain attack types or require specific security controls. Many now exclude 'acts of war' after recent nation-state attacks. Carefully review policy exclusions and ensure coverage matches your risk profile. Some insurers provide free security assessments.",
                    "Consider cyber insurance if you handle sensitive data, have online operations, or face regulatory requirements. Small businesses are frequent targets and often underinsured. Premiums have risen sharply due to increasing ransomware claims. Insurers now require multi-factor authentication, backups, and other controls. Some offer breach coaching and response teams. Document your security measures - insurers may deny claims if negligence is proven."
                ]
            }
        }
    
    def get_response(self, user_input):
        user_input = user_input.lower().strip()
        
        # Check for greetings
        if any(greeting in user_input for greeting in self.greetings):
            return random.choice([
                f"Hello! I'm {self.name}, your cybersecurity assistant. How can I help?",
                f"Hi there! I'm {self.name}. Ask me anything about cybersecurity.",
                f"Greetings! I'm {self.name} version {self.version}, ready to discuss cybersecurity topics.",
                f"Welcome to {self.name}! I can help with phishing, malware, ransomware, and other security concerns."
            ])
            
        # Check for goodbyes
        if any(goodbye in user_input for goodbye in self.goodbyes):
            return random.choice([
                "Stay secure! Let me know if you have more cybersecurity questions.",
                "Goodbye! Remember to practice good cyber hygiene and keep your software updated.",
                "Signing off! Enable those security updates and be cautious with email attachments.",
                "Until next time! Consider enabling multi-factor authentication on your important accounts."
            ])
        
        # Check time/date questions
        if "time" in user_input or "date" in user_input:
            now = datetime.now()
            return f"The current date and time is {now.strftime('%A, %B %d, %Y at %I:%M %p')}. Remember to check your system clock is accurate for proper security certificate validation."
        
        # Check for specific cybersecurity topics
        for topic, data in self.knowledge_base.items():
            if re.search(data["question"], user_input):
                return random.choice(data["answer"])
        
        # Default response if no match found
        return random.choice([
            "I'm not sure about that specific cybersecurity topic. Could you rephrase or ask about something else? I cover phishing, malware, passwords, VPNs, and more.",
            "That's an interesting question. I currently have detailed information on: phishing, malware, ransomware, firewalls, 2FA, social engineering, and other security topics.",
            "I don't have enough information to answer that precisely. Try asking about specific cybersecurity concepts like encryption, zero trust, or DDoS protection.",
            "Cybersecurity is a broad field. Could you narrow your question? I can discuss technical defenses, policy issues, or user education aspects of digital security."
        ])

# Main chat loop
def main():
    bot = CyberSecurityChatbot()
    print(f"{bot.name} v{bot.version} - Cybersecurity Chatbot")
    print("Type 'quit', 'exit', or 'bye' to end the chat.\n")
    print("I can discuss: phishing, malware, passwords, ransomware, VPNs, 2FA, firewalls,")
    print("social engineering, DDoS, IoT security, zero trust, encryption, dark web, and cyber insurance.\n")
    
    while True:
        user_input = input("You: ")
        if user_input.lower() in bot.goodbyes:
            print(f"{bot.name}: {bot.get_response(user_input)}")
            break
        
        response = bot.get_response(user_input)
        print(f"{bot.name}: {response}")

if __name__ == "__main__":
    main()
