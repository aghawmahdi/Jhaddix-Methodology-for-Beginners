# Jhaddix-Methodology-for-Beginners

# Jhaddix

### How to Shot Web - Defcon 23

In his DEF CON 23 presentation "How to Shot Web", Jason Haddix discussed the different ways to hack websites and mobile apps. He covered a wide range of topics, including:

**Philosophy**: Haddix emphasizes the importance of having a good understanding of the underlying technologies involved in web and mobile development. To effectively identify and exploit vulnerabilities, a hacker needs to be familiar with programming languages, web frameworks, networking protocols, and mobile app architectures. Understanding how these technologies work allows the hacker to think like an attacker and identify potential weaknesses.

**Discovery**: Haddix discussed a number of techniques for finding vulnerabilities, such as fuzzing, directory brute-forcing, and parameter tampering.

- Fuzzing: Fuzzing is a testing technique that involves sending random or malformed data to a target application to identify potential vulnerabilities. This can help uncover issues like buffer overflows, input validation errors, and memory leaks. Fuzzing can be performed manually or using automated tools.
- Directory brute-forcing: Directory brute-forcing is a technique used to discover hidden directories and files on a web server. Attackers use tools to systematically try different directory and file names, looking for a valid response from the server. This can help reveal sensitive information or hidden functionality that may be vulnerable to exploitation.
- Parameter tampering: Parameter tampering involves manipulating input parameters, such as URL query strings, form fields, or cookies, to bypass security controls or access unauthorized functionality. Attackers may try different combinations of values or use special characters to trigger errors or unexpected behavior in the target application.
- Content discovery: Content discovery is the process of identifying and exploring the various components of a web or mobile application. This can include walking through the app's user interface, analyzing JavaScript code, and using tools to spider or crawl the application to find hidden resources. Content discovery can help reveal potential attack surfaces and vulnerabilities.
- Web fuzzing & analyzing fuzzing results: Web fuzzing involves sending various inputs to web application parameters and paths to identify potential vulnerabilities. Analyzing the results of fuzzing can help identify issues such as injection vulnerabilities, access control flaws, and other security weaknesses.
- Vulnerability automation: Vulnerability automation involves using tools and scripts to automatically scan and test applications for known vulnerabilities. This can include checking for known CVEs (Common Vulnerabilities and Exposures), using dynamic scanners, and analyzing dependencies. Automation can help speed up the discovery process and allow security testers to focus on manual testing and more complex vulnerabilities.

**Mapping**: Once a vulnerability has been found, it is important to map out its scope and impact. This can be done by using tools like Burp Suite and OWASP ZAP.

- Burp Suite: Burp Suite is a widely used web application security testing tool that helps identify vulnerabilities and verify the security of web applications. It offers various features, such as a proxy server, a web vulnerability scanner, an intruder tool for automated attacks, a repeater tool for manual testing, and a sequencer tool for analyzing the randomness of session tokens. Burp Suite allows security testers to intercept, analyze, and modify HTTP and HTTPS requests and responses, which helps in understanding the application's behavior and identifying potential vulnerabilities.
- OWASP ZAP (Zed Attack Proxy): OWASP ZAP is an open-source web application security testing tool developed by the OWASP (Open Web Application Security Project) community. It is designed to help security professionals and developers identify vulnerabilities in their web applications. ZAP provides various features, such as an intercepting proxy, an automated scanner, a passive scanner, a fuzzer, and a scripting engine. These features enable testers to intercept and modify web traffic, scan applications for known vulnerabilities, and perform custom attacks using scripts.

Both Burp Suite and OWASP ZAP can be used for mapping the application's attack surface and understanding its structure. This process typically involves:

- Crawling: Crawling the application to discover its pages, links, and resources. This can be done using the built-in spider functionality in both tools, which automatically follows links and identifies resources within the application.
- Intercepting and analyzing traffic: Intercepting and analyzing HTTP and HTTPS requests and responses to understand the application's behavior, data flow, and potential vulnerabilities. Both Burp Suite and OWASP ZAP provide an intercepting proxy that allows testers to view and modify web traffic in real-time.
- Identifying entry points: Identifying the various entry points in the application, such as form fields, URL parameters, and cookies, which can be potential targets for attacks.
- Testing for vulnerabilities: Using the built-in scanners and fuzzers in both tools to test the identified entry points for known vulnerabilities, such as SQL injection, cross-site scripting, and file inclusion.

**Tactical fuzzing**: Haddix discussed a number of specific attacks that can be used to exploit vulnerabilities, such as SQL injection, cross-site scripting (XSS), and file inclusion (LFI).

- SQL Injection: SQL injection is a technique where attackers inject malicious SQL code into a web application to manipulate its database. This can allow unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. Attackers typically study the targeted database by submitting various values into the query to observe the server's response. Successful SQL injection attacks can enable attackers to modify database information, access sensitive data, perform administrative activities on the database, and recover files from the database.
- Cross-site Scripting (XSS): XSS is an attack in which an attacker injects malicious executable scripts into the code of a trusted application or website. This can be done by sending a malicious link to a user and enticing them to click on it. If the app or website lacks proper data sanitization, the malicious link executes the attacker's chosen code on the user's system, potentially allowing the attacker to steal the user's active session cookie or other sensitive information
- File Inclusion (LFI): Local File Inclusion is an attack technique in which attackers trick a web application into either running or exposing files on a web server. LFI attacks can expose sensitive information and, in severe cases, lead to cross-site scripting (XSS) and remote code execution. LFI typically occurs when an application uses the path to a file as input without proper validation, allowing an attacker to include malicious files by manipulating the input

**CSRF**: Haddix also discussed cross-site request forgery (CSRF), a type of attack that can be used to trick users into performing actions without their knowledge.

Cross-Site Request Forgery (CSRF) is a type of attack that tricks users into performing actions on a web application without their knowledge or consent. This is achieved by exploiting the trust that a web application has in an authenticated user. In a CSRF attack, the attacker usually uses social engineering techniques, such as sending a malicious link via email or chat, to trick users into clicking on it and executing the attacker's desired actions.

Here's a detailed explanation of CSRF attacks:

1. CSRF Attack Mechanism: The attacker crafts a malicious request that targets a specific action on a vulnerable web application. This request is designed to look like a legitimate request from an authenticated user. The attacker then sends the malicious request to the victim, typically through social engineering techniques like phishing emails or malicious links.
2. Exploiting Trust: When the victim clicks on the malicious link or interacts with the attacker's content, the victim's browser sends the request to the targeted web application. Since the victim is already authenticated on the web application, the application processes the request as if it were a legitimate action initiated by the victim.
3. Unintended Actions: As a result of the CSRF attack, the victim unknowingly performs actions on the web application that they did not intend to perform. These actions can include changing their password, making unauthorized purchases, or transferring funds to the attacker's account.

**Web services**: Haddix briefly discussed the security of web services. He noted that web services are often overlooked by security teams, but they can be just as vulnerable as traditional web applications.

1. Insecure communication: Web services often transmit sensitive data between the client and server. To protect this data, it is essential to use secure communication protocols, such as HTTPS and SSL/TLS encryption.
2. Authentication and authorization: Web services should implement strong authentication and authorization mechanisms to ensure that only authorized users can access the service and perform actions. This can include using secure tokens, multi-factor authentication, and role-based access control.
3. Input validation: Web services should validate and sanitize all user input to prevent attacks such as SQL injection, cross-site scripting (XSS), and XML external entity (XXE) attacks. This can be achieved by using input validation libraries, regular expressions, and whitelisting allowed input.
4. Error handling: Web services should implement proper error handling to prevent information disclosure and other security issues. This includes returning generic error messages, logging errors securely, and monitoring logs for potential security incidents.
5. Security misconfigurations: Web services should be configured securely to prevent unauthorized access and other security issues. This includes disabling unnecessary services, removing default accounts and passwords, and keeping software up-to-date with the latest security patches.
6. Components with known vulnerabilities: Web services often rely on third-party components, such as libraries and frameworks. It is essential to keep these components up-to-date and monitor for known vulnerabilities to prevent potential attacks.

**Mobile vulnerabilities**: Haddix also discussed some of the specific vulnerabilities that are found in mobile apps. These vulnerabilities can be exploited to gain access to sensitive data or take control of the device.
Use a variety of tools and techniques to find vulnerabilities. No single tool or technique is perfect, so it is important to have a broad toolkit.

1. Improper Platform Usage: Incorrect use of  mobile platforms and available security controls can lead to severe consequences, such as allowing a threat actor to exploit a cross-site scripting (XSS) vulnerability.
2. Insecure Data Storage: Storing sensitive data without proper encryption or protection can lead to unauthorized access and data breaches.
3. Insecure Communication: Unsecured data transfer between the mobile app and a server can be intercepted and manipulated by attackers.
4. Insecure Authentication: Weak or insufficient authentication mechanisms can allow unauthorized users to access sensitive information or perform malicious actions.
5. Insufficient Cryptography: Using weak or outdated cryptographic algorithms can make it easier for attackers to decrypt sensitive data.
6. Client-Side Injection: Vulnerabilities in the client-side code can be exploited to inject malicious code or manipulate app functionality.
7. Security Misconfigurations: Incorrect security settings or configurations can create vulnerabilities that attackers can exploit.
8. Inadequate Logging: Insufficient logging and monitoring can make it difficult to detect and respond to security incidents

Additionally, Haddix emphasizes the need for creativity and persistence. Hacking requires thinking outside the box and exploring unconventional attack vectors. It's not just about following predefined methodologies but also about constantly adapting and trying new approaches to uncover vulnerabilities that may have been overlooked.

* **Be persistent**. Don't give up easily when looking for vulnerabilities. Sometimes it takes a lot of time and effort to find a working exploit.

- Hacking often requires trying multiple different approaches before finding something that works. You may need to spend a lot of time probing and analyzing a system before discovering any viable attack vectors.
- Don't give up after initial failures. Persistently trying different inputs, exploit techniques, and tools is key. Look to uncover overlooked weaknesses through thorough and relentless testing.
- Be prepared to invest significant time and effort before achieving a successful intrusion. Hacking complex systems can involve a lot of trial and error.

* **Be creative**. Don't be afraid to think outside the box when looking for vulnerabilities. Sometimes the most creative attacks are the most successful.

- Think outside the box when approaching a system. Don't just follow standard procedures or exploit known vulnerabilities. Come up with novel attack ideas and vectors.
- Try combining tools and techniques in creative ways to achieve your goal. Mash together different exploits and scripts to maximize effectiveness.
- Customize and modify existing exploits and tools to apply them in creative ways against the target. Tweak inputs, payloads, and technical approaches.
- Leverage features in unintended ways to uncover unexpected weaknesses. Look at all components of a system in depth for any potential openings.

* **Stay up-to-date on the latest security threats**. The web security landscape is constantly changing, so it is important to stay up-to-date on the latest threats.

- Regularly review security advisories and vulnerability databases to stay informed on newly discovered bugs and exploits.
- Follow security research publications and hacking forums to learn about the latest attack techniques as they are developed.
- Make sure to update and patch systems frequently to close security holes as vendors become aware of them.
- Test systems against new exploits quickly when they are made public to detect if they are still vulnerable.
- Sign up for services that provide timely vulnerability alerts and information on emerging cyber threats.

### The bug Hunter’s Methodology v4.0 - Recon Edition NahamCon

In his NahamCon 2020 talk "The Bug Hunter's Methodology v4.0 - Recon Edition", Jason Haddix presented his four-step methodology for finding bugs in web applications. The four steps are:

1. **Recon:** The goal of this step is to gather as much information as possible about the target application, including its subdomains, infrastructure, and technologies. This information can be used to identify potential vulnerabilities.
    - Subdomain enumeration tools: These tools help identify subdomains associated with the target domain, which can reveal additional attack surfaces. Examples of such tools are Sublist3r, Amass, and Subfinder.
    - Port scanning tools: Port scanners like Nmap and Masscan help identify open ports and services running on the target's infrastructure, providing insights into potential vulnerabilities.
    - Web application fingerprinting tools: Tools like Wappalyzer and BuiltWith can help identify the technologies used by the target application, such as web servers, content management systems, and JavaScript libraries. This information
    can be used to find known vulnerabilities in these technologies.
    - Directory and file enumeration tools: Tools like Dirsearch, Gobuster, and ffuf can help discover hidden directories and files on the target application, potentially revealing sensitive information or vulnerable endpoints.
    - Search engines and public databases: Bug hunters can use search engines like Google and Shodan, as well as public databases like the Wayback Machine and Certificate Transparency logs, to gather additional information about the target application and its infrastructure.
2. **Enumeration:** The goal of this step is to identify all of the possible entry points into the application. This includes things like login pages, API endpoints, and file upload forms.
    - Common entry points: Some typical entry points include login pages, registration forms, password reset forms, search bars, file upload forms, and API endpoints. Identifying these entry points helps bug hunters understand the application's functionality and potential attack surfaces.
    - Entry points identification: Bug hunters can use tools like Burp Suite, OWASP ZAP, or Fiddler to intercept and analyze HTTP requests and responses between the client and the server. This allows them to identify entry points, parameters, and potential vulnerabilities.
    - Tools and techniques: Some popular tools for identifying entry points include:
        - Directory and file enumeration tools like Dirsearch, Gobuster, and ffuf, which help discover hidden directories and files on the target application.
        - Web application fingerprinting tools like Wappalyzer and BuiltWith, which help identify the technologies used by the target application and find known vulnerabilities in these technologies.
        - Web vulnerability scanners like Nikto, Arachni, and Vega, which can help identify potential vulnerabilities in web applications.
3. **Exploitation:** The goal of this step is to exploit any vulnerabilities that have been found. This can be done by manually testing the application or using automated tools.
    - Manual testing: Bug hunters often manually test the application by manipulating input fields, parameters, and URLs to trigger unexpected behavior or bypass security controls. This can involve techniques such as SQL injection, cross-site scripting (XSS), and cross-site request forgery (CSRF).
    - Automated tools: Bug hunters can use automated tools to help identify and exploit vulnerabilities. Some popular tools include:
        - Web vulnerability scanners like Nikto, Arachni, and Vega, which can help identify potential vulnerabilities in web applications.
        - Dynamic application security testing (DAST) tools like Burp Suite, OWASP ZAP, or Fiddler, which can analyze HTTP requests and responses between the client and the server, identify entry points, parameters, and potential vulnerabilities.
        - Static application security testing (SAST) tools, which analyze the source code of the application to identify potential security issues.
4. **Reporting:** The goal of this step is to report any vulnerabilities that have been found to the responsible party. This can be done through a bug bounty program or through a responsible disclosure policy.
    - Clear and concise description: When reporting a vulnerability, it is essential to provide a clear and concise description of the issue, including the affected component, the type of vulnerability, and the potential impact on the application or its users.
    - Steps to reproduce: Include detailed steps to reproduce the vulnerability, along with any necessary prerequisites or conditions. This helps the responsible party understand and validate the issue, making it easier for them to address the vulnerability.
    - Proof of concept: If possible, provide a proof of concept (PoC) that demonstrates the vulnerability in action. This can be in the form of code snippets, screenshots, or video recordings.
    - Suggested remediation: Offer suggestions for fixing the vulnerability, based on industry best practices or your own research. This can help the responsible party address the issue more quickly and effectively.
    - Responsible disclosure: Follow the responsible disclosure policy of the affected organization or platform, if available. This typically involves giving the responsible party a reasonable amount of time to address the vulnerability before publicly disclosing the issue.

Haddix also discussed a number of specific techniques that can be used during each of these steps. For example, during the recon step, he recommended using tools like Shodan and Censys to search for subdomains and infrastructure information. During the enumeration step, he recommended using tools like Dirbuster and Wfuzz to identify potential entry points. And during the exploitation step, he recommended using tools like Burp Suite and OWASP ZAP to identify and exploit vulnerabilities.

- Shodan - A search engine that lets you find specific types of computers/servers connected to the internet using various filters. Can help find web servers, databases, and other infrastructure associated with the target app.
- Censys - Similar to Shodan. Lets you search for websites/servers based on software, ports, protocols etc. Useful for reconnaissance.
- Dirbuster - A web content scanner that looks for hidden directories and files on websites by brute forcing URLs. Helps uncover hidden parts of sites.
- Wfuzz - A web application fuzzer that can brute force parameters, directory names, and file names on web apps. Useful for finding hidden API endpoints, pages etc.

Haddix's methodology is a comprehensive and practical approach to finding bugs in web applications. It is a valuable resource for anyone who is interested in learning more about bug bounty hunting or web security.

Here are some additional tips from Haddix's talk:

- Start with a good understanding of the target application. This includes knowing what the application does, who uses it, and what its security requirements are.
This means that before you start testing an application for security vulnerabilities, you need to understand what the application is designed to do, who its intended users are, and what kind of information it processes and stores. This will help you understand where potential vulnerabilities might be. For instance, if the application handles sensitive user data, then data protection and privacy would be key areas of focus. Understanding the application's functionality will also help you identify non-typical use cases that could potentially be exploited.
- Be patient and persistent. It takes time and effort to find bugs. Don't give up easily.
Security testing is a time-consuming process. It's not always possible to find vulnerabilities immediately. Sometimes, a potential vulnerability might take hours or even days to uncover. This tip emphasizes the importance of not giving up easily and continuing to test different parts of the application and different types of attacks until you find the vulnerabilities. Patience and persistence are key traits of successful security testers.
- Be creative. Don't be afraid to think outside the box when looking for vulnerabilities. Sometimes the most creative attacks are the most successful.
This tip highlights the importance of thinking outside the box when looking for vulnerabilities. Traditional methods of attack might not always yield results, especially for applications that have been designed with security in mind. Therefore, it's important to come up with new and creative ways to try and exploit potential vulnerabilities. This could involve thinking of non-standard use cases, combining different types of attacks, or even trying to exploit the application in ways that the developers might not have anticipated.
- Stay up-to-date on the latest security threats. The web security landscape is constantly changing, so it is important to stay up-to-date on the latest threats.
The landscape of web security is constantly changing, with new vulnerabilities and attack methods being discovered all the time. Therefore, it's important to stay informed about the latest developments in the field. This could involve reading security blogs, attending conferences, or participating in online forums. By staying up-to-date, you can ensure that you're equipped with the latest knowledge and techniques to identify and exploit vulnerabilities in the applications you're testing.

### The Bug Hunter’s Methodology Application Analysis - HackerOne

- Review the application - Manually test and review the functionality of the application to understand what it does and how it works. Look at all pages and features.
- Identify entry points - Find all the ways users can interact with the application. This includes things like login forms, search bars, URLs/endpoints, etc. These are potential areas to test.
- Map the attack surface - Outline the different parts of the application that can be tested. This includes the client-side, server-side, APIs, mobile apps, etc. Knowing the scope is important.
- Fingerprint the technologies - Identify the languages, frameworks, libraries, servers and other technologies used to build the app. This can give insights into how to test it and what vulnerabilities may exist.
- Discover hidden content - Use tools like Dirbuster to brute force directories and find hidden files/pages that may not be linked or easily accessible. Expanding the attack surface.
- View page source - Manually review frontend code for clues about backends, APIs, debug comments, etc. Also look for plaintext passwords or other sensitive data.
- Inspect traffic - Use a proxy like Burp to intercept traffic between the client and server. Analyze requests/responses for interesting parameters, headers, cookies, etc.
- Test configurations - Try modifying settings like HTTP headers, URL parameters, cookies, form fields etc. to see how the app handles it. May reveal unexpected access, data leakage etc.

Jason Haddix's The Bug Hunter's Methodology - Application Analysis is a comprehensive approach to discovering and exploiting vulnerabilities in web applications and mobile apps. The methodology is divided into several sections, including reconnaissance, application analysis, mapping, authorization and sessions, tactical fuzzing, privilege, transport and logic, web services, and mobile vulnerabilities. Here is a breakdown of the methodology:

1. **Reconnaissance**: This phase involves gathering information about the target application, such as its domain, subdomains, IP addresses, and technologies used. This information can be obtained using various tools and techniques, such as DNS enumeration, web scraping, and Google dorking.
2. **Application Analysis**: In this phase, the security tester analyzes the application's structure, functionality, and potential vulnerabilities. This can be done using tools like Burp Suite and OWASP ZAP, as well as manual testing techniques.
3. **Mapping**: Mapping involves understanding the application's attack surface and identifying potential entry points for attacks. This can be achieved by crawling the application, intercepting and analyzing web traffic, and identifying form fields, URL parameters, and cookies.
4. **Authorization and Sessions**: This phase focuses on testing the application's authentication and authorization mechanisms, such as secure tokens, multi-factor authentication, and role-based access control.
5. **Tactical Fuzzing**: Tactical fuzzing involves exploiting specific vulnerabilities, such as SQL injection, cross-site scripting (XSS), and file inclusion (LFI), using targeted attacks.
6. **Privilege, Transport, and Logic**: This phase involves testing the application's privilege management, secure communication protocols, and business logic to identify potential security issues.
7. **Web Services**: Web services security testing focuses on identifying vulnerabilities in web services, such as insecure communication, authentication and authorization issues, and input validation.
8. **Mobile Vulnerabilities**: This phase involves testing mobile applications for potential vulnerabilities, such as insecure data storage, weak encryption, and insecure communication.

Citations:
[1] [https://youtube.com/watch?v=FqnSAa2KmBI](https://youtube.com/watch?v=FqnSAa2KmBI)
[2] [https://youtube.com/watch?v=HmDY7w8AbR4](https://youtube.com/watch?v=HmDY7w8AbR4)
[3] [https://github.com/jhaddix/tbhm](https://github.com/jhaddix/tbhm)
[4] [https://youtube.com/watch?v=fvQ8RWoK_Z0](https://youtube.com/watch?v=fvQ8RWoK_Z0)
[5] [https://twitter.com/jhaddix?lang=en](https://twitter.com/jhaddix?lang=en)
[6] [https://twitter.com/Jhaddix/status/1520446531312128000?lang=en](https://twitter.com/Jhaddix/status/1520446531312128000?lang=en)
[7] [https://infosecwriteups.com/bug-bounty-hunting-methodology-toolkit-tips-tricks-blogs-ef6542301c65](https://infosecwriteups.com/bug-bounty-hunting-methodology-toolkit-tips-tricks-blogs-ef6542301c65)
[8] [https://www.trickster.dev/post/notes-from-the-bug-hunters-methodology-application-analysis-v1/](https://www.trickster.dev/post/notes-from-the-bug-hunters-methodology-application-analysis-v1/)

Now we want check the whole map:

Methodology:

1. **Reconnaissance**
This phase involves gathering information about the target system or organization. It includes passive activities like searching for publicly available data on search engines, social media, and public records. Active reconnaissance techniques might involve DNS enumeration, subdomain discovery, and network scanning. The goal is to gather a comprehensive picture of the target's digital footprint.

![Untitled](Jhaddix%20f9d050543b124326890cf0010c1c2990/Untitled.png)

1. **Discovery**
In this step, the focus is on identifying the specific assets of the target. These assets can include web applications, APIs, servers, subdomains, and more. The purpose is to create a list of potential entry points that could be vulnerable to attacks.
    1. Discovery Techniques:
        1. Network scanning
        Network scanning involves sending packets to a target network to discover active hosts, open ports, and services running on those ports. This helps identify the live hosts within the target's network and provides information about the services they're running. Network scanning can be performed using tools like Nmap and can include techniques like ping sweeps and ARP scans.
        2. Port scanning
        Port scanning is a subset of network scanning. It involves probing a target system's ports to determine which ports are open, closed, or filtered. Open ports indicate services that are actively listening and can potentially be accessed by attackers. Different types of port scans, such as TCP, UDP, and SYN scans, can provide varying levels of information about a target's services.
        3. Service enumeration
        Service enumeration is the process of identifying the specific services running on the open ports of a target system. This is important because knowing the services helps security researchers understand the potential attack vectors and vulnerabilities associated with those services. Techniques involve sending specific requests to services and analyzing their responses to determine the exact services and their versions.
        4. Web application scanning
        Web application scanning involves automated tools that crawl through web applications, sending requests to various pages and endpoints to identify potential vulnerabilities. These tools can detect issues like SQL injection, cross-site scripting (XSS), and insecure configurations. Scanning web applications helps to uncover vulnerabilities that might not be easily identifiable through manual analysis.
        5. Web spidering
        Web spidering is a technique used to systematically explore a web application by following links between web pages. This helps in mapping out the structure of the application and identifying all accessible pages and endpoints. Spidering can be part of automated web application scanning, helping researchers gather a comprehensive view of the application's functionality.
        6. Fingerprinting
        Fingerprinting, also known as banner grabbing, involves collecting information from service banners or responses from network services. This information can reveal details about the software and versions being used, which aids in understanding the technology stack. This knowledge can help researchers identify known vulnerabilities associated with specific versions.
    2. Vulnerability Scanning:
        1. Identify known vulnerabilities
        This involves using databases of known vulnerabilities, such as the National Vulnerability Database (NVD) or commercial vulnerability databases, to compare the target's software versions with known vulnerable versions. If a match is found, it indicates that the target could be vulnerable to a specific attack. Vulnerability scanners use these databases to recognize potentially exploitable weaknesses.
        2. Assess security weaknesses
        In addition to identifying known vulnerabilities, vulnerability scanners also look for security weaknesses that might not be tied to specific known vulnerabilities. These weaknesses can include insecure configurations, weak passwords, open ports, or outdated software. Assessing security weaknesses provides a broader view of the target's risk profile beyond just known vulnerabilities.
        3. Conduct automated scans
        Automated scans are performed by vulnerability scanning tools. These tools systematically probe the target's network, services, and applications to identify vulnerabilities and security issues. Automated scans are efficient for covering a large number of assets and finding common vulnerabilities across the target's environment.
        4. Assess vulnerability severity
        Not all vulnerabilities have the same impact. Some vulnerabilities might have a higher severity level due to the potential impact they could have on the system's confidentiality, integrity, and availability. Vulnerability scanners typically assess the severity of identified vulnerabilities, often using a scoring system like the Common Vulnerability Scoring System (CVSS). This helps prioritize which vulnerabilities should be addressed first.
        5. Generate detailed reports
        After conducting scans and assessing vulnerabilities, vulnerability scanners generate detailed reports. These reports provide a comprehensive overview of the vulnerabilities found, including their severity, affected systems, and potential consequences. The reports also include recommendations for remediation. A well-structured report is crucial for communicating findings to the target organization's stakeholders, including technical teams and management.
    3. Authentication Vulnerabilities
        1. Weak or default passwords
        Weak passwords are passwords that are easily guessable or can be cracked quickly using common techniques like dictionary attacks or brute force. Default passwords are often set by manufacturers for initial access and are meant to be changed by users. Attackers target systems where default passwords are still in use or where users have chosen weak passwords, as these make unauthorized access easier.
        2. Brute-forcing
        Brute-forcing is an attack method where an attacker systematically tries all possible combinations of characters to guess a password. It's an automated process that relies on the sheer volume of attempts to eventually find the correct password. Attackers use powerful computers and specialized software for this purpose. Defending against brute force attacks involves implementing account lockouts or rate limiting to prevent excessive login attempts.
        3. Credential stuffing
        Credential stuffing is an attack where attackers use leaked usernames and passwords from one breach to try and gain unauthorized access to other accounts where users have reused the same credentials. Since many people reuse passwords across different platforms, attackers can exploit this behavior to gain access to multiple accounts.
        4. Authentication bypass
        Authentication bypass occurs when attackers find a way to circumvent the authentication process altogether and gain unauthorized access to a system or application. This might involve exploiting a vulnerability or misconfiguration that allows them to access restricted areas without providing valid credentials.
        5. Password reuse
        Password reuse is a risky behavior where users employ the same password across multiple accounts or systems. If one of those accounts is compromised, attackers can potentially use the same credentials to gain access to other accounts as well. This practice increases the impact of a security breach.
    4. Authorization Vulnerabilities
        1. Insecure direct object references
        Insecure Direct Object References (IDOR) occur when an attacker is able to manipulate input or parameters to access resources they are not authorized to access. This might involve modifying URLs or input fields to access sensitive data or functionality that should be restricted. Proper authorization checks should be in place to ensure that users can only access resources they are authorized to access.
        2. Privilege escalation
        Privilege escalation involves gaining higher levels of access or permissions than intended. This can occur in various ways, such as exploiting vulnerabilities that allow an attacker to elevate their privileges from a standard user to an administrator or superuser. Privilege escalation can lead to unauthorized control over systems, data, or functionalities.
        3. Insecure access controls
        Insecure access controls occur when the mechanisms that enforce authorization are poorly implemented or not robust. This might include improper configuration of user roles and permissions, allowing users to access functionalities or data they shouldn't have access to. Inadequate access controls can lead to unauthorized access and potential data breaches.
        4. Horizontal privilege escalation
        Horizontal privilege escalation involves an attacker gaining access to the same level of privileges as another user but on a different account. For example, an attacker might exploit a vulnerability to gain access to another user's account with the same level of permissions. This can be used to impersonate users and perform actions on their behalf.
        5. Vertical privilege escalation
        Vertical privilege escalation occurs when an attacker gains higher levels of privileges than they initially had. This might involve exploiting a vulnerability to move from a standard user role to an administrative role within an application or system. Vertical privilege escalation can lead to complete control over a system or application.
    5. Injection Vulnerabilities
        1. SQL injection
        SQL injection is a type of vulnerability where an attacker manipulates user inputs to inject malicious SQL queries into an application's database query. If the application does not properly sanitize and validate user inputs, attackers can execute unintended SQL commands, potentially gaining unauthorized access to the database, retrieving, modifying, or deleting data, or even taking control of the entire application.
        2. Command injection
        Command injection occurs when an attacker injects malicious commands into an application that is executed by the underlying system's command shell. This typically happens when user inputs are not properly validated or sanitized. Successful command injection can lead to execution of arbitrary commands on the host system, potentially allowing attackers to gain control over the system.
        3. XSS (Cross Site Scripting)
        Cross-Site Scripting is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. This happens when an application fails to properly validate and sanitize user inputs before rendering them back to users. The injected scripts are then executed in the context of the victim's browser, potentially stealing sensitive information or performing actions on behalf of the victim.
        4. LDAP injection
        LDAP injection occurs in applications that use LDAP (Lightweight Directory Access Protocol) to interact with directory services. Attackers manipulate user inputs to inject malicious LDAP queries. If the application does not properly validate or sanitize these inputs, attackers can access unauthorized data or execute unintended operations within the directory service.
        5. XML injection
        XML injection is a vulnerability that occurs when an attacker injects malicious XML content into an application's input fields that process XML data. If the application does not properly validate or sanitize user inputs, attackers can manipulate XML data structures, potentially causing the application to expose sensitive information, perform unintended actions, or even disrupt its normal behavior.
    6. Cross-Site Vulnerabilities
        1. Cross-Site Scripting (XSS)
        Cross-Site Scripting (XSS) is a vulnerability that occurs when an attacker injects malicious scripts into a web application. These scripts are then executed in the context of other users' browsers when they visit the affected page. XSS vulnerabilities arise when the application fails to properly validate or sanitize user inputs before rendering them in web pages. This can lead to the theft of sensitive information, session hijacking, or performing actions on behalf of the victim.
        2. Cross-Site Forgery (CSRF)
        Cross-Site Forgery (CSRF) is an attack where an attacker tricks a user into unknowingly performing actions on a web application without their consent. This is achieved by getting the victim to click on a specially crafted link or visit a malicious page while they are authenticated in the target application. The application then executes actions on behalf of the user without their knowledge, potentially leading to unintended changes or actions.
        3. Clickjacking
        Clickjacking involves disguising a malicious action beneath an apparently harmless or legitimate interface. The victim is tricked into clicking on an element that performs an unintended action without their knowledge. This is achieved by overlaying transparent or hidden elements on top of visible content. Clickjacking can be used to perform actions like making unauthorized transactions or changing account settings.
        4. Cross-Origin Resource Sharing (CORS)
        Cross-Origin Resource Sharing (CORS) is a security mechanism that governs how web browsers allow web pages in one origin to request resources from another origin. Without proper CORS configuration, attackers could potentially exploit the browser's same-origin policy to make unauthorized requests to a different domain, leading to data leakage or unauthorized access to resources.
        5. Cross-Site Script Inclusion (XSSI)
        Cross-Site Script Inclusion (XSSI) is a vulnerability related to the improper handling of untrusted JSON data returned from third-party domains. If an application includes this data in its script content, it can lead to the execution of malicious scripts in the context of the application. This can result in the theft of sensitive data or other security breaches.
    7. Security Misconfiguration
        1. Default configurations
        Default configurations are the settings and configurations that software, systems, or applications come with out of the box. Leaving default configurations unchanged can pose a security risk because attackers are often familiar with these defaults and can exploit them. To mitigate this, it's important to review and adjust default configurations to align with security best practices before deploying any system or software.
        2. Unnecessary services
        Unnecessary services are services or features that are enabled or installed but not needed for the system's intended functionality. These services can create additional attack vectors, increasing the potential for vulnerabilities. It's important to disable or remove any services that are not required to minimize the attack surface and potential risks.
        3. Directory listing
        Directory listing occurs when a web server displays the contents of a directory to users instead of showing an index page or denying access. This can expose sensitive information, internal file structures, and potentially reveal files that were not intended to be publicly accessible. Proper server configuration and disabling directory listing are essential to prevent unauthorized access to directory contents.
        4. Insecure file permissions
        Insecure file permissions occur when files and directories have overly permissive access controls, allowing unauthorized users to read, modify, or execute them. This can lead to data leakage, unauthorized modifications, or even remote code execution. Properly setting file and directory permissions according to the principle of least privilege is crucial to prevent unauthorized access.
        5. Error messages leakage
        Error messages can inadvertently reveal sensitive information about a system's architecture, technology stack, or internal workings. Attackers can use this information to better plan their attacks. It's important to configure error messages to provide minimal details to users and developers, while avoiding the disclosure of sensitive information that could aid attackers.
    8. File Inclusion Vulnerability
        1. Local file inclusion (LFI)
        Local File Inclusion (LFI) is a vulnerability that occurs when an attacker is able to include files located on the same server as the vulnerable application. This is usually possible when the application allows user-supplied input, such as file paths or parameters, to be included in its code without proper validation or sanitization. Attackers can manipulate these inputs to traverse the file system and include arbitrary files, potentially exposing sensitive information or executing malicious code.
        2. Remote file inclusion (RFI)
        Remote File Inclusion (RFI) is similar to LFI, but in this case, attackers are able to include files from remote servers into the vulnerable application's code. This occurs when the application uses user-supplied input to dynamically load external resources without proper validation. Attackers can exploit this to include malicious files from their own servers, leading to unauthorized access, data leakage, or remote code execution.
        3. Path traversal
        Path Traversal is a technique used to exploit vulnerabilities that allow attackers to traverse directories and access files or resources outside the intended scope. This occurs when an application does not properly sanitize user-supplied inputs used in file paths, URLs, or other filesystem-related operations. Attackers can manipulate these inputs to "escape" from the intended directory and access files in other directories, potentially exposing sensitive data or executing unauthorized actions.
    9. Cryptographic Vulnerabilities
        1. Weak encryption algorithms
        Weak encryption algorithms are algorithms that are no longer considered secure due to advances in cryptography and the discovery of vulnerabilities. Using weak encryption algorithms can lead to data being easily decrypted by attackers, rendering the encryption ineffective. It's important to use encryption algorithms that are currently considered strong and resistant to attacks, such as AES (Advanced Encryption Standard).
        2. Weak key management
        Weak key management involves improper handling of encryption keys, such as using weak passwords or storing keys in insecure locations. If encryption keys are easily guessable or compromised, attackers can gain access to encrypted data. Proper key management practices, such as using strong and unique keys, regular rotation, and secure storage, are crucial for maintaining the security of encrypted data.
        3. Insecure storage of sensitive information
        Sensitive information, such as passwords or cryptographic keys, should be stored securely. Storing them in plaintext or with weak encryption can lead to unauthorized access. Sensitive information should be properly hashed and salted before storage, and encryption should be used to protect data at rest.
        4. Insecure random number generation
        Secure cryptographic operations often rely on the generation of random numbers. If random number generation is weak or predictable, it can compromise the security of cryptographic protocols. Cryptographically secure random number generators (CSPRNGs) should be used to ensure that generated numbers are unpredictable and resistant to attacks.
        5. Use of outdated or vulnerable cryptographic libraries
        Using outdated or vulnerable cryptographic libraries can expose systems to known vulnerabilities or weaknesses. Attackers can exploit these vulnerabilities to bypass encryption or perform cryptographic attacks. It's crucial to keep cryptographic libraries up to date and follow best practices for secure implementation.
    10. Business Logic Vulnerabilities
        1. Insecure session management
        Insecure session management occurs when an application does not properly manage user sessions, leading to vulnerabilities such as session fixation or session hijacking. Attackers can exploit these weaknesses to impersonate users, gain unauthorized access, or perform actions on behalf of other users. Proper session management practices, including secure session token generation, session expiration, and proper logout mechanisms, are essential to mitigate these vulnerabilities.
        2. Inadequate input validation
        Inadequate input validation occurs when an application fails to properly validate and sanitize user inputs. This can lead to a range of vulnerabilities, including injection attacks, cross-site scripting (XSS), and other security issues. Proper input validation and sanitization are crucial to prevent attackers from manipulating inputs to execute malicious actions.
        3. Insufficient process validation
        Insufficient process validation involves not validating or verifying important processes or transactions within the application. This can lead to vulnerabilities such as business logic flaws, where attackers can abuse the application's logic to perform unauthorized actions or gain improper access. Proper validation and verification of critical processes are essential to prevent misuse and unauthorized actions.
        4. Insecure data storage and retrieval
        Insecure data storage and retrieval involve improper handling of sensitive data, such as storing sensitive information in plaintext, using weak encryption, or not following secure storage practices. Attackers can exploit these weaknesses to gain unauthorized access to sensitive data. Proper encryption, hashing, and secure storage practices are crucial to protect sensitive data.
    11. Denial of Service (DoS) Vulnerabilities
        1. SYN flood
        SYN flood is a type of DoS attack where an attacker sends a large number of SYN (synchronization) requests to a target server, overwhelming its resources and preventing it from responding to legitimate requests. Since the server is waiting for ACK (acknowledgment) responses that never arrive, its resources become exhausted, causing a denial of service.
        2. Buffer overflow
        Buffer overflow attacks target vulnerabilities in a program's memory allocation. Attackers send more data to a buffer than it can handle, causing the excess data to overwrite adjacent memory areas. This can lead to the corruption of program execution, crashes, and potential denial of service. In some cases, attackers might use buffer overflows to execute arbitrary code.
        3. HTTP flood
        HTTP flood attacks involve sending a massive number of HTTP requests to a web server, consuming its resources and causing it to slow down or crash. This type of attack can be launched using a botnet, where multiple compromised devices flood the target server with requests, overwhelming its capacity to handle them.
        4. Slowloris
        Slowloris is an attack that targets web servers by keeping numerous connections open with minimal data sent in each request. This ties up the server's resources, as it waits for the slow requests to complete. Slowloris attacks exploit the limitations of the server's maximum concurrent connections, leading to a denial of service.
        5. DNS amplification
        DNS amplification attacks involve sending small requests to open DNS servers with a spoofed source IP address. The server responds with a larger response to the victim's IP address, amplifying the traffic sent to the target. These attacks can lead to overwhelming amounts of data being sent to the target, causing a denial of service.
    12. Additional Vulnerabilities
        1. Information disclosure
        Information disclosure vulnerabilities involve the unintentional exposure of sensitive data to unauthorized users. This could include revealing system configurations, passwords, personally identifiable information (PII), or other confidential data. Attackers exploit these vulnerabilities to gather information that can be used for further attacks or exploitation.
        2. Remote code execution
        Remote Code Execution (RCE) vulnerabilities occur when attackers are able to execute arbitrary code on a target system from a remote location. These vulnerabilities can allow attackers to take full control of the system, potentially leading to unauthorized access, data breaches, or even complete compromise of the system.
        3. Broken authentication and session management
        Broken authentication and session management vulnerabilities arise when an application's authentication and session mechanisms are improperly implemented or can be easily bypassed. Attackers can exploit these vulnerabilities to impersonate legitimate users, gain unauthorized access, or hijack user sessions.
        4. XML external entity (XXE) attack
        XML External Entity (XXE) attacks target applications that parse XML input without proper validation. Attackers can exploit this by including malicious XML entities that lead to unauthorized information disclosure, denial of service, or even remote code execution. Proper input validation and disabling external entities are essential to prevent XXE attacks.
        5. Server-side request forgery (SSRF)
        Server-Side Request Forgery (SSRF) vulnerabilities occur when an attacker can manipulate an application to make requests to internal or external resources on behalf of the application. This can lead to unauthorized data retrieval, access to internal services, and potential further exploitation.
    
2. **Enumeration**
Enumeration is about extracting detailed information about the identified assets. This phase may involve techniques such as banner grabbing (collecting information from service banners), port scanning, and identifying the technologies in use. The goal is to gain a deeper understanding of the target's architecture and potential attack vectors.
    1. **Information Gathering**:
        
        refers to the process of collecting data and information about a target system, application, or network. This phase is crucial for understanding the potential attack surface and identifying vulnerabilities that might exist within the target.
        
        During the enumeration or information gathering phase of bug bounty hunting, security researchers aim to gather as much relevant information as possible to aid in their assessment. This can include:
        
        1. **Domain and Subdomain Discovery:** Identifying all the domains and subdomains associated with the target. This can involve DNS enumeration and searching for publicly available records.
        2. **Network Scanning:** Scanning the target's network to identify active hosts, open ports, and services running on those ports. This helps researchers understand the infrastructure.
            
            Network scanners are tools used in cybersecurity to analyze and assess the security of computer networks. These tools help security professionals identify active hosts, open ports, services running on those ports, and potential vulnerabilities present within the network. Network scanners are valuable for various purposes, including network management, vulnerability assessment, and penetration testing. Here's a more detailed explanation of network scanners:
            
            **Functionality:**
            Network scanners work by sending requests or probes to network devices, such as computers, servers, routers, and other networked devices. They listen for responses and gather information about the devices' configuration, services, and potential vulnerabilities. Some common functions of network scanners include:
            
            1. **Host Discovery:** Network scanners help identify active hosts within a given IP range or subnet. They send out ICMP (Ping) requests or other network packets to determine whether a host is online and responsive.
            2. **Port Scanning:** Port scanning involves sending requests to various ports on a target system to identify which ports are open and listening for incoming connections. Different types of scans, such as TCP, UDP, and SYN scans, provide varying levels of information about the target's network services.
            3. **Service Detection:** Once open ports are identified, network scanners attempt to determine the services running on those ports. This is done by analyzing the responses received from the target devices. Service detection helps understand the software and versions in use, aiding in vulnerability assessment.
            4. **OS Fingerprinting:** Some advanced network scanners can attempt to determine the operating system of the target based on how it responds to various network probes. This can help attackers identify potential targets with known vulnerabilities.
            
            **Types of Network Scanners:**
            Network scanners can be categorized into three main types based on their level of aggressiveness and interaction with the target:
            
            1. **Ping Sweep Scanners:** These scanners send ICMP Echo Request (Ping) packets to discover active hosts on the network. They're relatively non-intrusive but may not provide detailed information about services or vulnerabilities.
            2. **Port Scanners:** Port scanners send network packets to target hosts and analyze their responses to determine which ports are open. Different scanning techniques, like TCP SYN, TCP Connect, and UDP scans, provide varying levels of information.
            3. **Vulnerability Scanners:** These scanners go beyond identifying open ports and services. They also attempt to identify vulnerabilities associated with the services running on the identified ports. Vulnerability scanners can help security professionals identify weaknesses that could be exploited by attackers.
            
            **Usage:**
            Network scanners are widely used for various purposes, including:
            
            - **Network Inventory:** Scanners help administrators maintain an up-to-date inventory of devices connected to the network.
            - **Security Auditing:** Organizations use network scanners to perform security assessments, identifying potential vulnerabilities and misconfigurations.
            - **Penetration Testing:** Ethical hackers and penetration testers use network scanners to simulate attacks and discover weak points in a network's defenses.
            - **Incident Response:** During security incidents, network scanners can be used to identify compromised hosts and assess the extent of the breach.
        3. **Service Fingerprinting:** Determining the versions and types of services running on open ports. This information helps in identifying potential vulnerabilities associated with specific software versions.
        4. **Web Application Crawling:** Crawling through web applications to map out their structure, identify endpoints, and understand the application's functionality.
        5. **Directory and File Enumeration:** Identifying directories, files, and resources that are publicly accessible. This can reveal sensitive information that attackers might exploit.
        6. **Subdomain Takeover:** Identifying subdomains that might be vulnerable to subdomain takeover attacks, where an attacker can gain control over a subdomain.
        7. **Social Engineering and OSINT:** Gathering information from publicly available sources, social media, and other online resources to learn about the target's employees, technologies, and potential weaknesses.
            
            Social engineering is a psychological manipulation technique used by attackers to deceive individuals into divulging confidential information, performing actions, or making decisions that may compromise security. It exploits human psychology, emotions, and tendencies to influence victims to bypass security measures, disclose sensitive data, or grant unauthorized access. Social engineering attacks don't necessarily rely on technical vulnerabilities; instead, they exploit human vulnerabilities. Here are some common social engineering techniques:
            
            1. **Phishing:** Attackers send deceptive emails, messages, or websites that impersonate legitimate entities to trick users into revealing sensitive information like passwords, credit card details, or account credentials.
            2. **Pretexting:** Attackers create fabricated scenarios or stories to gain the trust of victims. This could involve posing as a colleague, tech support personnel, or a trusted authority figure to extract information.
            3. **Baiting:** Attackers offer something enticing, such as free software, to lure victims into downloading malicious files or clicking on links that lead to malware.
            4. **Quid Pro Quo:** Attackers promise something in exchange for information or action, like offering technical assistance in exchange for login credentials.
            5. **Tailgating/Piggybacking:** Attackers physically follow authorized personnel into restricted areas by posing as a colleague or needing help, bypassing security controls.
            
            **Open-Source Intelligence (OSINT):**
            Open-Source Intelligence (OSINT) is the practice of collecting and analyzing information from publicly available sources to gain insights about individuals, organizations, systems, and vulnerabilities. OSINT sources include social media, websites, forums, news articles, government databases, and more. OSINT is used for a variety of purposes, including cybersecurity, threat intelligence, investigations, and reconnaissance. Here are some key aspects of OSINT:
            
            1. **Data Collection:** OSINT involves systematically gathering information from diverse sources. This can include identifying potential attack vectors, understanding an organization's online footprint, and even uncovering previously unknown vulnerabilities.
            2. **Threat Profiling:** OSINT can help security professionals profile potential threats by gathering information about threat actors, their motives, and their capabilities.
            3. **Vulnerability Discovery:** OSINT can lead to the discovery of vulnerabilities by uncovering misconfigurations, weak points in online assets, and security weaknesses.
            4. **Reconnaissance:** OSINT is often used as a reconnaissance technique before launching attacks or assessments. It provides attackers with information to tailor their approach to exploit target weaknesses.
            5. **Cyber Threat Intelligence:** OSINT feeds into threat intelligence by providing context, trends, and insights into potential cyber threats and attack patterns.
        8. **Technology Stack Identification:** Identifying the technologies, frameworks, and software in use. This helps researchers search for known vulnerabilities associated with these technologies.
        9. **Error Message Analysis:** Analyzing error messages returned by the application or server, which might inadvertently reveal system information or configuration details.
        10. **Email Harvesting:** Identifying email addresses associated with the target organization. Email addresses can be used in social engineering or targeted attacks.
        11. **API Endpoint Identification:** Identifying API endpoints in web applications and their potential vulnerabilities.
    2. **Passive**:
        
        refers to a method of gathering information about a target system, application, or network without actively interacting with it. Unlike active enumeration, which involves actively probing and scanning the target, passive enumeration focuses on collecting publicly available information from external sources without directly interacting with the target itself. This approach is intended to reduce the risk of causing disruptions or triggering security alarms on the target system.
        
        Passive enumeration techniques typically involve the use of open-source intelligence (OSINT) and publicly accessible tools to gather information. Some common techniques in passive enumeration include:
        
        1. **WHOIS Lookups:** Gathering registration information about domain names, including details about the domain owner, registration date, and contact information.
            
            A WHOIS lookup is a query or search performed to retrieve information about a domain name or an IP address from a public database known as the WHOIS database. The WHOIS database contains registration and ownership details of domain names, IP addresses, and other related information. It's an important tool for identifying and verifying information about internet resources. Here's a more detailed explanation of WHOIS lookups:
            
            **Functionality:**
            A WHOIS lookup provides valuable information about domain names and IP addresses, including:
            
            1. **Domain Name Registration:** WHOIS can reveal who registered a domain name, their contact information, the registration date, and expiration date.
            2. **Domain Name Servers (DNS):** WHOIS includes information about the authoritative DNS servers that handle the domain's DNS records.
            3. **Administrative and Technical Contacts:** Contact information for administrative, technical, and billing purposes associated with the domain registration.
            4. **Domain Status:** The current status of the domain, such as whether it's active, pending renewal, or expired.
            5. **Registrar Information:** Details about the registrar that managed the domain registration.
            6. **IP Address Allocation:** For IP addresses, WHOIS can provide information about the allocation, registration, and location of the IP range.
            
            **Usage:**
            WHOIS lookups have several practical applications:
            
            1. **Domain Ownership Verification:** Individuals and organizations can use WHOIS to verify the ownership of a domain before engaging in transactions or business deals.
            2. **Domain Research:** Researchers and analysts use WHOIS to gather intelligence about domain portfolios, trends, and potential security risks.
            3. **Abuse Reporting:** If a domain is involved in malicious activities, abuse reports can be submitted to the domain's registrar or hosting provider using WHOIS information.
            4. **Security Investigations:** Cybersecurity professionals use WHOIS to gather information during security investigations, such as identifying potential threat actors or malicious infrastructure.
            5. **Brand Protection:** Organizations use WHOIS to monitor the registration of domain names that might infringe on their trademarks or brand names.
            6. **Legal and Dispute Resolution:** WHOIS information can be used in legal disputes related to domain ownership, trademark infringement, and other internet-related issues.
        2. **Domain and Subdomain Discovery:** Identifying domains and subdomains associated with the target through tools like subdomain enumeration services and search engines.
            
            Domain and subdomain discovery is the process of identifying and mapping out the hierarchy of domain names and their associated subdomains within a given target organization or network. This practice is essential for understanding an organization's online presence, identifying potential security risks, and performing thorough cybersecurity assessments. Here's a deeper look into domain and subdomain discovery:
            
            **Domain:**
            A domain is a human-readable name that corresponds to a unique numeric IP address on the internet. Domains are used to identify websites, email servers, and other online resources. For example, in the domain name "example.com," "example" is the second-level domain, and ".com" is the top-level domain (TLD).
            
            **Subdomain:**
            A subdomain is a domain that is part of a larger domain. It appears as a prefix to the main domain name and is separated by a dot. Subdomains are often used to organize and categorize content on a website or to point to specific services or resources. For example, "blog.example.com" is a subdomain of "example.com."
            
            **Domain and Subdomain Discovery Techniques:**
            Domain and subdomain discovery involves various techniques to identify all relevant domain names and subdomains associated with a target organization:
            
            1. **DNS Zone Transfers:** Some DNS servers are misconfigured and allow zone transfers, which can reveal a list of subdomains associated with a domain.
            2. **Passive DNS Analysis:** Passive DNS databases store historical DNS data, helping to uncover subdomains and changes over time.
            3. **Brute Force Subdomain Enumeration:** Attackers use automated tools to systematically generate and test subdomain names to find active ones.
            4. **Search Engines:** Using advanced search operators on search engines like Google, Bing, and DuckDuckGo can reveal subdomains with publicly accessible content.
            5. **Certificate Transparency Logs:** TLS/SSL certificates often include subdomain information, which can be accessed via certificate transparency logs.
            6. **Third-Party Services:** Some services provide subdomain discovery as a service, scanning public sources to find subdomains associated with a target.
            7. **Public DNS Records:** DNS records such as MX, CNAME, and NS records can reveal subdomains and their purpose.
            8. **Social Media and OSINT:** Information from social media profiles and publicly available sources might hint at subdomains used by an organization.
            
            **Importance and Applications:**
            Domain and subdomain discovery have several critical applications:
            
            1. **Security Assessment:** Identifying subdomains helps assess the attack surface and vulnerabilities of an organization's online assets.
            2. **Threat Intelligence:** Discovering subdomains associated with threat actors or malicious campaigns aids in threat intelligence efforts.
            3. **Branding and Trademark Protection:** Monitoring subdomains helps protect brands from abuse, phishing, or domain squatting.
            4. **Incident Response:** During security incidents, identifying relevant subdomains can assist in tracing the scope and impact of a breach.
            5. **Penetration Testing:** Pen testers use subdomain discovery to simulate real-world attacks and evaluate an organization's defenses.
            6. **Domain Management:** Organizations use subdomain discovery to manage and consolidate their online presence efficiently.
        3. **Social Media Analysis:** Collecting information from social media profiles, public posts, and other online resources that might reveal information about the target organization, its employees, and its technologies.
            
            Social media analysis, also known as social media intelligence or social media monitoring, refers to the process of collecting, analyzing, and extracting insights from social media platforms and online communities. This practice is used by individuals, businesses, marketers, researchers, and security professionals to understand trends, sentiments, conversations, and interactions occurring on social media platforms. Social media analysis provides valuable insights for various purposes, including marketing strategies, brand management, market research, and cybersecurity. Here's a more detailed look at social media analysis:
            
            **Functionality and Techniques:**
            
            1. **Data Collection:** Social media analysis involves gathering data from various social media platforms, including Facebook, Twitter, Instagram, LinkedIn, Reddit, and more. This data can include posts, comments, hashtags, images, videos, and other user-generated content.
            2. **Sentiment Analysis:** Sentiment analysis involves using natural language processing (NLP) techniques to determine the sentiment expressed in social media posts. This helps assess whether the sentiment is positive, negative, or neutral towards a particular topic, brand, or event.
            3. **Topic Analysis:** By analyzing the content of social media posts, researchers can identify trending topics, discussions, and emerging themes within specific communities or across the entire platform.
            4. **Influencer Identification:** Social media analysis can identify individuals or accounts with a significant following who have the potential to influence conversations and trends. Businesses often collaborate with influencers to promote products or services.
            5. **Brand Monitoring:** Organizations monitor social media platforms to track mentions of their brand, products, or services. This helps them understand public perception, respond to customer feedback, and manage reputation.
            6. **Crisis Management:** During a crisis, social media analysis can help organizations gauge public sentiment, address concerns, and adapt communication strategies.
            7. **Market Research:** Businesses use social media analysis to gather insights into customer preferences, behaviors, and trends, helping them make informed decisions about products and services.
            8. **Competitor Analysis:** By monitoring competitors' social media activities, organizations can gain insights into their strategies, engagement levels, and customer interactions.
            
            **Challenges:**
            
            - **Data Volume:** The sheer volume of data on social media platforms can be overwhelming, requiring efficient tools and techniques for data collection and analysis.
            - **Data Privacy:** Ethical considerations and privacy concerns arise when collecting and analyzing user-generated content. Compliance with data protection regulations is essential.
            - **Noise and Irrelevance:** Sorting through irrelevant or spammy content can be a challenge, especially when trying to identify meaningful insights.
        4. **Online Documentation and Publicly Available Information:** Searching for and analyzing any public documentation, whitepapers, technical articles, and forum posts related to the target.
        5. **Publicly Available Vulnerability Databases:** Searching for known vulnerabilities related to the target's technologies, software, and services in publicly available vulnerability databases.
        6. **Passive DNS Analysis:** Analyzing DNS records for subdomains and historical data to understand the target's infrastructure.
        Passive DNS analysis involves collecting and analyzing historical DNS data to gain insights into domain names, IP addresses, and their associated changes over time. Unlike active DNS queries that directly interact with DNS servers, passive DNS analysis relies on data collected from DNS transactions that have occurred in the past. This data is stored in passive DNS databases and can be valuable for security research, threat intelligence, and incident response.
            
            Key points about passive DNS analysis:
            
            - **Historical Data:** Passive DNS databases store information about DNS resolutions, allowing researchers to see how domain names were resolved to IP addresses in the past.
            - **Insight into Changes:** Passive DNS analysis provides insights into changes made to domain configurations, IP address changes, and potential infrastructure shifts.
            - **Threat Intelligence:** By analyzing historical DNS data, security professionals can uncover patterns related to malicious activities, command and control (C2) servers, domain changes associated with attacks, and more.
            - **Incident Response:** During security incidents, passive DNS analysis can help trace the origins of attacks, identify malicious domains, and assess the scope of a breach.
            
            **DNS Lookups:**
            DNS lookups are queries made to the Domain Name System (DNS) to resolve human-readable domain names into their corresponding IP addresses. DNS is essential for translating domain names into numerical IP addresses that computers can understand and use to locate resources on the internet.
            
            There are two main types of DNS lookups:
            
            1. **Forward DNS Lookup:** This is the most common type of DNS lookup, where a domain name is input, and the DNS resolver returns the associated IP address.
            2. **Reverse DNS Lookup:** Also known as a "PTR lookup," this involves providing an IP address and retrieving the corresponding domain name. This is especially useful for verifying the identity of an IP address and understanding the hostname associated with it.
            
            **Reverse DNS Lookups:**
            Reverse DNS lookups involve querying DNS records to find the domain name associated with a given IP address. While traditional DNS lookup goes from domain name to IP address, reverse DNS works in the opposite direction.
            
            Key points about reverse DNS lookups:
            
            - **Identifying Hostnames:** Reverse DNS lookups can provide information about the hostname associated with an IP address, which can be helpful in understanding server identities.
            - **Email Server Verification:** Reverse DNS is often used to verify that an email server has a valid hostname associated with its IP address. This can help reduce the likelihood of spam or phishing emails.
            - **Security Analysis:** Reverse DNS lookups can assist in identifying potential misconfigurations or inconsistencies in DNS records, which may indicate security risks.
            - **IP Address Verification:** In cybersecurity investigations, reverse DNS lookups can be used to validate whether an IP address is associated with legitimate infrastructure.
        7. **Email Harvesting:** Identifying email addresses associated with the target organization, which can be useful for social engineering or targeted attacks.
        8. **Shodan and Censys Searches:** Utilizing search engines like Shodan and Censys to discover information about open ports, services, and exposed devices associated with the target's IP addresses.
    3. **Google Dorking**:
        
        Google dorking, also known as Google hacking or Google-fu, refers to the practice of using advanced search operators and techniques to perform precise and targeted searches on the Google search engine. It involves crafting specific queries to uncover information that might not be readily accessible through conventional searches. Google dorking can reveal sensitive information, vulnerabilities, and potentially exploitable data that might be inadvertently exposed on the internet. However, it's important to note that Google dorking should only be used for ethical and legitimate purposes, as exploiting vulnerabilities without permission is illegal.
        
        **Key Concepts and Techniques:**
        
        1. **Advanced Search Operators:** Google provides a variety of search operators that allow users to refine their searches and retrieve more specific results. For example, using "site:" operator limits the search results to a specific website or domain.
        2. **Filetype Searches:** By using the "filetype:" operator, users can search for specific file types (e.g., PDF, DOC, XLS) on the internet. This can potentially reveal sensitive documents or information.
        3. **Inurl and Intitle:** Operators like "inurl:" and "intitle:" allow users to search for keywords within URLs or titles of web pages, which can lead to specific information being exposed.
        4. **Site Enumeration:** Using "site:" followed by a domain name can help identify subdomains, directories, and pages associated with a specific website.
        5. **Cache and Wayback Machine:** By viewing cached or archived versions of web pages, users can access content that might have been removed or changed.
    4. **Active:**
        
        Active enumeration involves actively probing a target system, network, or service to gather information about its configuration, availability, and potential vulnerabilities. This approach directly interacts with the target, sending network packets and analyzing responses. Active enumeration techniques can provide more detailed and accurate information than passive techniques but may also be more intrusive and can trigger security alerts.
        
        **Port Scanning:**
        Port scanning is a type of active enumeration that involves sending network packets to a target system's IP address to identify which ports are open, closed, or filtered. This information helps security professionals understand the services running on those ports and assess potential vulnerabilities. Different types of port scans provide varying levels of information:
        
        1. **TCP Connect Scan:** This type of scan establishes a full connection with each target port. If the connection is successful, the port is considered open; if it's rejected, the port is closed.
        2. **TCP SYN Scan (Half-open Scan):** This scan sends SYN packets (the first step in a TCP handshake) and analyzes the responses. It's more stealthy than a TCP Connect Scan but may not provide as much information.
        3. **UDP Scan:** UDP ports are often used for services that don't require a full connection. This scan sends UDP packets and analyzes the responses to determine if the port is open or closed.
        
        **Banner Grabbing:**
        Banner grabbing is a technique used after port scanning to extract information from the service or application running on an open port. When a connection is established, services often send a banner or response that reveals information about the service and its version. This information can help attackers identify potential vulnerabilities associated with specific software versions.
        
        **Ping Sweeps:**
        Ping sweeps are a type of active enumeration used to identify active hosts within a range of IP addresses. The goal is to determine which hosts are online and responsive. This is often achieved by sending ICMP Echo Request (Ping) packets to different IP addresses and analyzing the responses. While ping sweeps can quickly identify active hosts, they might not provide detailed information about services running on those hosts.
        
    5. **Vulnerability Scanners**:
        
        Vulnerability scanning is the process of identifying security weaknesses, vulnerabilities, and misconfigurations in computer systems, networks, and applications. Vulnerability scanners are tools designed to automate this process by scanning systems for known vulnerabilities, often leveraging databases of known vulnerabilities and attack patterns. Enumeration, in the context of vulnerability scanning, refers to the process of systematically identifying and listing potential security issues on a target system.
        
        **Enumeration in Application Scanners:**
        Application scanners focus on identifying vulnerabilities within software applications. Enumeration in this context involves systematically assessing the application's functionalities, inputs, and outputs to identify potential attack vectors. For instance, if an application accepts user input, the scanner might test for common vulnerabilities like SQL injection, Cross-Site Scripting (XSS), and more. Enumeration helps the scanner comprehensively assess the application's attack surface and identify potential entry points for exploitation.
        
        **Web Vulnerability Scanners:**
        Web vulnerability scanners specifically target web applications to identify security weaknesses. These scanners perform automated tests by sending various inputs and payloads to web forms, URLs, and other elements of a web application. Enumeration in web vulnerability scanning involves thoroughly exploring the application's components, such as forms, parameters, headers, and cookies, to uncover potential vulnerabilities.
        
        **SSL/TLS Scanners:**
        SSL/TLS scanners focus on identifying security issues related to SSL/TLS encryption protocols, which are crucial for securing data transmission over the internet. These scanners evaluate SSL/TLS configurations and certificates to ensure they adhere to best practices and security standards. Enumeration in SSL/TLS scanning involves assessing cipher suites, SSL versions, and certificate details to uncover weaknesses that might lead to vulnerabilities like weak encryption, misconfigurations, or expired certificates.
        
    6. **Exploitation**:
        
        **Proof of Concept (PoC) Development:**
        A Proof of Concept (PoC) is a demonstration or prototype that validates the feasibility or functionality of a concept, idea, or vulnerability. In cybersecurity, PoC development involves creating a functional demonstration of how a particular vulnerability or exploit works. Exploitation enumeration within PoC development refers to the process of identifying the specific steps, techniques, and methods required to successfully exploit a vulnerability.
        
        **Exploit Databases:**
        Exploit databases are repositories of known vulnerabilities and their corresponding exploits. These databases store detailed information about vulnerabilities, including descriptions, technical details, and associated proof-of-concept code. Exploitation enumeration in this context involves searching and selecting an appropriate exploit from the database that matches the target vulnerability.
        
        **Manual Testing:**
        Manual testing is the process of evaluating software, systems, or networks by directly interacting with them rather than relying solely on automated tools. In the context of exploitation enumeration, manual testing involves hands-on investigation, analysis, and experimentation to identify potential attack vectors, vulnerabilities, and exploitation techniques.
        
        **Injection Attacks:**
        Injection attacks involve maliciously injecting malicious code or data into an application or system to exploit vulnerabilities and gain unauthorized access or control. Exploitation enumeration for injection attacks includes identifying the input points where user-controlled data is processed (e.g., SQL queries, command strings) and crafting payloads to manipulate the system behavior.
        
        **Privilege Escalation:**
        Privilege escalation refers to the process of gaining higher levels of access or privileges on a system than initially granted. Exploitation enumeration for privilege escalation involves identifying vulnerabilities or misconfigurations that can be exploited to elevate privileges, such as exploiting weak user permissions, misconfigured services, or known vulnerabilities.
        
    7. **Post-Exploitation:**
        
        Post-exploitation enumeration refers to the process of gathering information and exploring a compromised system or network after an initial breach has occurred. This phase comes after the attacker has gained unauthorized access and is aimed at maximizing their control, expanding their reach, and achieving their objectives within the compromised environment.
        
        **Data Exfiltration:**
        Data exfiltration involves the unauthorized transfer of sensitive or valuable data from a compromised system to an external location controlled by the attacker. Post-exploitation enumeration in data exfiltration involves identifying valuable data sources, creating channels for data transfer (such as command and control servers), and extracting data stealthily to avoid detection.
        
        **Persistence:**
        Persistence is the ability of an attacker to maintain their presence and control within a compromised system or network over an extended period. Post-exploitation enumeration in persistence involves identifying and implementing mechanisms that allow the attacker's access to persist even after system reboots, updates, or security measures are taken. This might involve creating backdoors, modifying startup scripts, or utilizing rootkits.
        
        **Lateral Movement:**
        Lateral movement is the process of moving horizontally across a network to access and compromise additional systems. Post-exploitation enumeration in lateral movement involves identifying potential target systems, exploiting vulnerabilities, and using compromised credentials to access other devices within the network. This enables the attacker to expand their influence and gather more sensitive information.
        
        **Pivoting:**
        Pivoting is a technique used to move traffic from a compromised system to other systems within a network, often through a chain of compromised hosts. Post-exploitation enumeration in pivoting involves identifying intermediate systems that can act as pivot points, establishing connections, and using them to gain access to more sensitive parts of the network that might be otherwise isolated.
        
    8. **Reporting**:
        
        **Comprehensive Report:**
        A comprehensive security report is a detailed document that outlines the findings, analysis, and recommendations resulting from a cybersecurity assessment or investigation. It provides a holistic view of the security posture, vulnerabilities, and potential risks within a system, network, or application.
        
        **Clear and Concise Language:**
        Clear and concise language is essential in a security report to ensure that the findings and recommendations are easily understood by various stakeholders, including technical and non-technical audiences. Using jargon-free language helps convey complex technical concepts accurately.
        
        **Detailed Vulnerability Descriptions:**
        Each identified vulnerability should be described in detail, including the technical specifics of the vulnerability, its underlying cause, and the methods used to discover it. This information provides context and clarity, enabling stakeholders to understand the nature of the issue.
        
        **Potential Impact Assessment:**
        A crucial component of a security report is assessing the potential impact of each identified vulnerability. This involves evaluating the severity of the vulnerability, understanding its potential consequences on confidentiality, integrity, and availability of data, and estimating the level of risk it poses to the organization.
        
        **Recommended Remediation Steps:**
        For each vulnerability, the report should include clear and actionable remediation steps. These steps guide the organization in addressing the identified issues and mitigating risks. Remediation recommendations should prioritize critical vulnerabilities that pose the highest risk.
        
    9. **Verification**:
        
        **Confirming Vulnerability Fixes:**
        Verification enumeration involves confirming whether the identified vulnerabilities have been successfully fixed or mitigated after the remediation process. This step ensures that the recommended actions were effectively implemented and that the security gaps have been addressed. It's important to verify that the fixes do not introduce new issues or inadvertently create other vulnerabilities.
        
        **Retesting Identified Vulnerabilities:**
        After vulnerabilities have been addressed, it's crucial to retest the affected systems or applications to ensure that the fixes were successful and that the vulnerabilities no longer exist. This process involves using the same techniques that initially identified the vulnerabilities to verify that they are no longer exploitable. If retesting confirms that vulnerabilities have been mitigated, it adds credibility to the remediation efforts.
        
        **Residual Risk Assessment:**
        Residual risk assessment is the process of evaluating the remaining risks after vulnerabilities have been mitigated or fixed. While some vulnerabilities might have been addressed, residual risk analysis helps organizations understand any remaining weaknesses or potential attack vectors. This analysis aids in prioritizing further security measures and understanding the level of risk that remains despite mitigation efforts.
        
        **Quality Assurance Checks:**
        Quality assurance checks involve reviewing the entire security assessment process, from vulnerability identification to verification, to ensure that the process was executed accurately and effectively. This step ensures the completeness and accuracy of the assessment and reporting. It also identifies areas for improvement in the assessment process itself.
        
    10. **Continual Improvement**:
        
        **Continual Improvement Enumeration:**
        Continual improvement enumeration involves the ongoing process of enhancing cybersecurity practices, methodologies, and approaches to stay ahead of emerging threats and challenges. This process emphasizes learning from experiences, adapting to changes, and incorporating new knowledge into security strategies.
        
        **Knowledge Sharing:**
        Knowledge sharing involves sharing insights, experiences, and expertise within an organization or the broader security community. Continual improvement enumeration includes actively participating in knowledge-sharing initiatives to disseminate information about vulnerabilities, exploits, best practices, and lessons learned.
        
        **Collaboration with the Security Community:**
        Collaboration within the security community fosters the exchange of information, expertise, and strategies. Engaging with fellow security professionals, researchers, and organizations enables the sharing of threat intelligence, mitigation techniques, and the latest developments in cybersecurity.
        
        **Keeping Up with New Techniques and Tools:**
        The field of cybersecurity is dynamic, with new attack techniques and tools emerging regularly. Continual improvement enumeration involves staying informed about the latest trends, vulnerabilities, and techniques used by attackers. This includes regularly updating skills, exploring new tools, and experimenting with different methodologies.
        
        **Feedback and Learning from Previous Engagements:**
        After completing security assessments, penetration tests, or incident response efforts, it's important to gather feedback from team members and stakeholders involved in the process. Learning from successes, challenges, and feedback contributes to refining approaches and strategies for future engagements.
        
        **Implementing Lessons Learned in Future Tests:**
        Continual improvement enumeration emphasizes applying lessons learned from previous engagements to future tests and assessments. This includes adopting improved methodologies, refining testing approaches, and avoiding common pitfalls encountered in the past.
        
3. **Vulnerability Assessment**
During this phase, researchers analyze the identified assets for vulnerabilities. They use various tools and methods to scan for common security issues such as SQL injection, cross-site scripting (XSS), and misconfigurations. The aim is to pinpoint weaknesses that could potentially be exploited by attackers.
4. **Exploitation**
Exploitation is where researchers attempt to take advantage of the identified vulnerabilities to gain unauthorized access or control. This step involves crafting and testing exploits to see if the vulnerabilities can indeed be abused. It requires a solid understanding of the vulnerabilities and potential attack vectors.
    1. Web Applications:
        1. Cross-Site Scripting (XSS)
        2. SQL Injection
        3. Cross-Site Request Forgery (CSRF)
        4. Remote Code Execution (RCE)
        5. Information Disclosure
        6. Server-Side Request Forgery (SSRF)
    2. Mobile Application:
        1. Insecure Data Storage
        2. Insecure Communication
        3. Insufficient Cryptography
        4. Code Injection
        5. Insecure Authentication and Authorization
        6. Privacy Violation
    3. Network:
        1. Man-in-the-Middle (MITM) Attacks
        2. Denial of Service (DoS)
        3. IP Spoofing
        4. DNS Spoofing
        5. Packet Sniffing
        6. Wireless Attacks
    4. Hardware:
        1. Physical Tampering
        2. Side Channel Attacks
        3. Malicious Add-ons
        4. Firmware Reverse Engineering
    5. Cloud:
        1. Misconfigurations
        2. Access Control Issues
        3. Data Breaches
        4. Insecure APIs
        5. DDoS Attacks
    6. IOT:
        1. Insecure Communication Protocols
        2. Weak Authentication
        3. Remote Code Execution
        4. Insecure Firmware
        5. Man-in-the-Middle Attacks
        6. Unauthorized Access
    7. Tools:
        1. Burp Suite
        2. OWASP ZAP
        3. Nmap
        4. Metasploit
        5. Wireshark
        6. SQLMap
        7. Nessus
        8. Kali Linux
        9. CMS Scanner
        10. Acunetix
5. **Post Exploitation**
After successfully exploiting a vulnerability, the focus shifts to maintaining and expanding control within the compromised system. This involves actions such as privilege escalation, lateral movement within a network, and data exfiltration. The goal is to demonstrate the potential impact an attacker could have after gaining access.
6. **Reporting**
The final phase involves creating a comprehensive report that documents the entire process. The report should include detailed information about the vulnerabilities discovered, the steps to reproduce them, potential consequences, and recommendations for remediation. A well-written report is crucial for the target organization to understand and address the security issues.

### The bug hunter's methodology TBHM Github

The Bug Hunter's Methodology (TBHM) is a collection of tips, tricks, tools, data analysis, and notes related to web application security assessments and bug hunting in bug bounties, created by Jason Haddix (Jhaddix). The methodology is divided into several sections, including Reconnaissance, Application Analysis, Mapping, Authorization and Sessions, Tactical fuzzing, Privilege, Transport and Logic, Web services, Mobile vulnerabilities, and others.

TBHM aims to provide up-to-date resources for bug hunters and web hackers to use during their day-to-day work. Jason Haddix has presented different versions of TBHM at various conferences, such as Defcon 23, NahamCon2020, and HacktivityCon2020. The methodology has evolved over time, with the latest version being TBHM v4 Recon Edition.

Some tools mentioned in TBHM v2 include Sublist3r, Brutesubs, Cloudflare_enum, GitRob, and TruffleHog for discovery and reconnaissance, as well as several BurpSuite plugins like VulnersCom, BackSlash-powered-scanner, Header Checks, pyschPATH, and HUNT Burp Suite Extension.

TBHM is an ongoing yearly installment that covers the newest tools and techniques for bug hunters and red teamers. It explores both common and lesser-known techniques to find assets for a target, such as finding a target's main seed domains, subdomains, IP space, and discussing cutting-edge tools and automation for each topic.

Citations:
[1] [https://github.com/jhaddix/tbhm](https://github.com/jhaddix/tbhm)
[2] [https://youtube.com/watch?v=FqnSAa2KmBI](https://youtube.com/watch?v=FqnSAa2KmBI)
[3] [https://github.com/danilabs/tools-tbhm](https://github.com/danilabs/tools-tbhm)
[4] [https://youtube.com/watch?v=HmDY7w8AbR4](https://youtube.com/watch?v=HmDY7w8AbR4)
[5] [https://github.com/jhaddix](https://github.com/jhaddix)
[6] [https://www.bugcrowd.com/resources/levelup/bug-bounty-hunter-methodology-v3/](https://www.bugcrowd.com/resources/levelup/bug-bounty-hunter-methodology-v3/)
[7] [https://youtube.com/watch?v=p4JgIu1mceI](https://youtube.com/watch?v=p4JgIu1mceI)
[8] [https://twitter.com/jhaddix?lang=en](https://twitter.com/jhaddix?lang=en)
[9] [https://gowthams.gitbook.io/bughunter-handbook/presentations](https://gowthams.gitbook.io/bughunter-handbook/presentations)
[10] [https://twitter.com/Jhaddix/status/1272306253113356288](https://twitter.com/Jhaddix/status/1272306253113356288)
[11] [https://youtube.com/watch?v=gIz_yn0Uvb8](https://youtube.com/watch?v=gIz_yn0Uvb8)
[12] [https://www.hacker101.com/conferences/hacktivitycon2020/tbhm.html](https://www.hacker101.com/conferences/hacktivitycon2020/tbhm.html)
