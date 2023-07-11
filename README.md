# Sweethoney - An Advance PE File Static Analysis Tool

## Overview
Sweethoney is a highly efficient Python application designed to facilitate automated file analysis. The application is developed by Matthew Schwartz, highly skilled cybersecurity specialists. It is proficient in performing comprehensive analyses of executable files, leveraging a vast array of alert categories to identify any potential suspicious behaviors.

## Delivering Impact and Efficiency
Sweethoney presents numerous advantages and drives substantial efficiency gains for users:
* Automation: The application streamlines and automates malware analysis, saving significant manual effort and time.
* Deep-Dive Analysis: By delving into the PE structure and alert-based detection, it unearths malicious indicators that might not be visible at a surface-level examination.
* Broad Spectrum Analysis: With its comprehensive array of alert categories, Sweethoney provides a broad spectrum analysis, thereby enhancing the detection capabilities.
* Rapid Response: The application's automated detection facilitates quicker identification of potential threats, enabling prompt and effective responses.
* Sweethoney offers a comprehensive, efficient, and financially transparent solution for querying the functionality and security implications of multiple APIs, potentially unearthing unknown security vulnerabilities. It excels in large-scale analyses due to its asynchronous operation, allowing it to handle multiple requests simultaneously and reduce processing time. It further boosts efficiency and cost-effectiveness by caching previous responses in a SQLite database to avoid unnecessary duplicate requests. The application also employs a robust rate limit handling mechanism through an exponential backoff strategy for uninterrupted operation. Importantly, its cost estimation feature empowers users with financial control, providing an estimation of potential charges prior to initiating requests.

## Key Features and Capabilities
* In-depth PE Analysis: Sweethoney uses the Python library pefile for parsing and editing PE (Portable Executable) files. This allows the application to delve into intricate details of the file structure and functionality, from section details, declared functions, to exported symbols and security features.
* Detection of Suspicious Behaviors: The application is equipped with alert lists targeting different potential malicious activities. These alerts encompass areas such as registry manipulation, networking & internet access, process & memory manipulation, and data theft, among others. Any matched behaviors are highlighted, offering users comprehensive visibility over potential security threats.
* Security Feature Check: Sweethoney inspects the security characteristics of the PE files, such as whether they use NX (No eXecute), ASLR (Address Space Layout Randomization), and High Entropy Sections, thereby assessing the file's security robustness.
* File Characteristics Assessment: Beyond security checks, the application also retrieves the PE file's information like compile time, SHA-1 hash, entropy, and many other attributes.
* Powerful string analysis tool, by extracting and analyzing strings from executable files, enables the detection of potential indicators of compromise (IoCs), such as IP addresses, URLs, file paths, registry keys, email addresses, and more. With its robust pattern-matching capabilities and efficient decoding techniques, the tool efficiently identifies potential IoCs, helping analysts uncover hidden threats and streamline the analysis process.
* The OpenAiUtils function harnesses the power of OpenAI’s GPT-3.5 Turbo model to aid users in understanding the purpose of APIs and their potential security implications. To use OpenAiUtils, you will need an API key from OpenAI. This key is used to authenticate requests to the OpenAI GPT-3.5 Turbo model. Please refer to OpenAI's documentation for information on how to obtain an API key. Once obtained, create a file named ```apikey.txt``` in the same directory as the Python files and store the API key in this file.
    * API Analysis: OpenAiUtils evaluates APIs associated with PE files to give the user insights about their usage and security context in relation to the MITRE ATT&CK framework.
    * Efficient Request Management: By using the aiohttp library, OpenAiUtils efficiently manages asynchronous HTTP requests to the OpenAI API, thereby achieving fast results.
    * Rate Limit Handling: The application gracefully handles rate limit issues. When rate limits are exceeded, the application automatically applies an exponential backoff strategy to retry the request, which increases efficiency and decreases the likelihood of failed requests.
    * Cache System: The application employs a SQLite database to cache previous responses, minimizing the need for duplicate requests and saving costs.
    * Cost Estimation: Prior to sending any requests, OpenAiUtils estimates the cost based on the number of requests to be made, giving users the chance to review and approve potential charges.  

Sweethoney is a powerful and efficient tool for file analysis, driving impact by providing users with a comprehensive, automated solution for enhancing their cybersecurity efforts.  Additionally by leveraging OpenAI's powerful language model, it provides insights that can be crucial for assessing potential security risks and vulnerabilities, thus driving impact and efficiency.

## Indicators of Compromise (IoC) includes:   
See fileUtils.py for the complete list of regex based IoCs:
* IPv4/IPv6 addresses
* URLs 
* Windows & Unix-like file paths
* Windows Registry keys
* HTTP user agents
* Email addresses
* Windows services
* Common malware commands (such as netsh, powershell, cmd, reg add, reg delete, certutil, ping, net, ipconfig, route, curl, wget, ftp, and cscript)
* Common JavaScript malware patterns (such as document.write, eval, constructor, window.setTimeout, window.setInterval, Function, WebSocket, and ActiveXObject)
* SQL injection patterns
* Shellcode patterns
* Hash patterns (MD5, SHA1, SHA256)
* SSH Public Key pattern & Private Key pattern

# Install required packages
Use the command below to install the packages according to the configuration file `requirements.txt`.

```
$ pip install -r requirements.txt
```

## Additional Resources
* [FLARE Obfuscated String Solver](https://github.com/mandiant/flare-floss)
* [readpe - PE Utils](https://github.com/mentebinaria/readpe)
* [Pestudio](https://www.winitor.com/)
* [XORSearch](https://blog.didierstevens.com/programs/xorsearch/)
* [Go Reverse Engineering Tool Kit](https://go-re.tk/)

