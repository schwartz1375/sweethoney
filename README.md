# Sweethoney - An Advance PE File Static Analysis Tool

## Overview
Sweethoney is a highly efficient Python application designed to facilitate automated file analysis. The application is developed by Matthew Schwartz, highly skilled cybersecurity specialists. It is proficient in performing comprehensive analyses of executable files, leveraging a vast array of alert categories to identify any potential suspicious behaviors.

## Delivering Impact and Efficiency
Sweethoney offers significant advantages, driving efficiency gains and impactful results for users by leveraging advanced AI platforms like Ollama and OpenAI:

* Flexibility in AI Platform Choice: Users have the flexibility to choose between the locally hosted Ollama platform and the cloud-based OpenAI services for querying API functionalities and assessing security implications. This choice allows users to leverage the strengths of each platform according to their specific needs. 
* Automation: The application streamlines the malware analysis process, significantly reducing manual effort and time. It automates the detection of malicious indicators within PE files, facilitating a more efficient analysis workflow.
* Comprehensive Analysis: Sweethoney delves deep into PE structures and employs a wide range of alert categories, enabling it to uncover malicious behaviors that might be overlooked in surface-level examinations.
* Rapid Threat Identification: Automated detection capabilities allow for quicker identification of potential threats, enabling timely and effective responses.
* Efficiency and Cost-Effectiveness: The application's asynchronous (OpenAI only, Ollama synchronous) is currently operation allows for handling multiple requests simultaneously, reducing processing time. It further enhances efficiency and cost management by caching previous responses in a SQLite database to avoid redundant queries. A robust rate limit handling mechanism, employing an exponential backoff strategy, ensures uninterrupted operation.
* Financial Transparency and Control: Sweethoney includes a cost estimation feature, providing users with an upfront estimation of potential charges before initiating requests. This empowers users to make informed decisions and maintain financial control over their analyses.

Sweethoney stands out as a comprehensive, efficient, and adaptable tool for static file analysis. By providing the option to utilize the analytical strengths of either Ollama or OpenAI, it equips users with powerful insights into the security implications of APIs and potential vulnerabilities, enhancing cybersecurity efforts with precision and scalability.

Note: While Ollama provides the advantage of local hosting, which can enhance data privacy and reduce reliance on external internet connections, its performance may vary based on the local hardware setup. In contrast, OpenAI's cloud-based services offer scalability and potentially faster response times, depending on network conditions and server load, but may involve considerations around data privacy and internet connectivity.

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

### Choosing Between Ollama and OpenAI
To clarify and tidy up the instructions for choosing between the Ollama platform or OpenAI within your Python script, consider the following revised version:
Choosing Between Ollama and OpenAI

To decide whether to use Ollama or OpenAI in your project, adjust the relevant lines in the sweethoney.py script. This configuration determines which platform and model your script will utilize for processing. The model settings for Ollama can be found and adjusted within ollamaUtils.py.
Example Configuration

Below is an example demonstrating how to select the Ollama platform with the Gemma model. To switch between Ollama and OpenAI, comment out one of the lines and uncomment the other in sweethoney.py as shown:

#### Instructions

1. OpenAI Configuration: If you prefer to use OpenAI, ensure that openAiUtils.py contains the necessary setup, including API keys and model selection. Uncomment the line that calls `openAiUtils.getOpenAiResults(pe)`.

2. Ollama Configuration: For using Ollama, make sure ollamaUtils.py is configured with the desired model (e.g., Gemma) and any other required settings. Uncomment the line that calls `ollamaUtils.getOpenAiResults(pe)`.

By following these instructions, you can easily switch between using the Ollama platform or OpenAI for your project's needs.

## Additional Resources
* [FLARE Obfuscated String Solver](https://github.com/mandiant/flare-floss)
* [readpe - PE Utils](https://github.com/mentebinaria/readpe)
* [Pestudio](https://www.winitor.com/)
* [XORSearch](https://blog.didierstevens.com/programs/xorsearch/)
* [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)
* [Go Reverse Engineering Tool Kit](https://go-re.tk/)

