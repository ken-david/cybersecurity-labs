# Malware Analysis: IOC Extraction (Static Analysis)

### Overview

This lab focused on performing **static malware analysis** on a suspicious Windows executable discovered during a simulated SOC incident. The objective was to determine whether the file exhibited malicious characteristics and to extract **Indicators of Compromise (IOCs)** that could support detection, containment, and escalation.

The investigation was conducted without executing the file, following standard SOC and malware-handling best practices.

### Scenario Summary

A suspicious executable posing as a legitimate system updater was identified on an endpoint. Security tooling raised alerts related to unusual behavior, prompting further analysis by the SOC.

As the analyst, my role was to:
- Validate whether the file was suspicious
- Identify malicious indicators
- Extract actionable IOCs
- Assess potential network-related behavior

### Techniques
- Static Analysis
- File metadata inspection
- Hash generation
- Import and string analysis

### Tools Used
- PeStudio – Initial static analysis and risk assessment
- CyberChef – Decoding and data transformation

## Analysis Process
### 1. File Triage & Initial Assessment

The executable was inspected using static analysis tooling to identify high-level properties such as:
- File architecture
- Cryptographic hashes
- Embedded metadata

This step helps determine whether the file matches known malicious samples and whether it aligns with the system it was found on.

<img width="729" height="504" alt="image" src="https://github.com/user-attachments/assets/afea1f8d-7e67-4066-9cbb-c28b566d0f5d" />



### 2. Indicator Discovery (Strings & Artifacts)

The next phase involved reviewing embedded strings and resources within the binary. This often reveals:
- Hardcoded URLs or domains
- Download locations
- Command-and-control indicators

Several network-related artifacts were identified that did not align with legitimate software update behavior. These artifacts are suitable for use as IOCs in detection systems.

<img width="780" height="345" alt="image" src="https://github.com/user-attachments/assets/4078d079-3e7d-49b1-aa0e-8ecd34e172af" />
<img width="688" height="196" alt="image" src="https://github.com/user-attachments/assets/4d6c0a5e-2f7d-4555-ac1a-a272c64df1b3" />



### 3. Network Capability Assessment

By analyzing imported libraries, the executable was found to load components associated with socket and network communication. This indicates the file likely has the capability to communicate externally, reinforcing suspicion of malicious intent.

<img width="712" height="231" alt="image" src="https://github.com/user-attachments/assets/e3769909-0df8-4df4-a76d-314b754d7833" />


### 4. Encoded Data Analysis

An obfuscated string associated with a suspicious domain was identified. Using decoding techniques, the data was transformed into readable content, demonstrating the importance of deobfuscation during malware triage.

This step highlights how attackers may attempt to hide meaningful information within binaries to evade casual inspection.

<img width="1052" height="323" alt="image" src="https://github.com/user-attachments/assets/f22cf202-23a9-4ca3-b36b-23d6767ca7fe" />


<img width="1634" height="663" alt="image" src="https://github.com/user-attachments/assets/db1cf509-67fe-4d66-bad8-475cefef0c33" />



## Key Takeaways

Through static analysis, several indicators suggested malicious behavior:
- The file impersonated a trusted system component
- Network-related artifacts were embedded in the binary
- External communication capabilities were present
- Obfuscated data required decoding for full context

This lab reinforced how static analysis alone can provide valuable insight during early-stage malware investigations, allowing SOC analysts to make informed decisions without executing potentially harmful files.

## Skills Demonstrated
- Static malware analysis methodology
- IOC identification and extraction
- Use of industry-relevant tools
- Analytical thinking and documentation

## Final Notes

This exercise mirrors real-world SOC workflows, where analysts often work with incomplete information and must rely on careful inspection, contextual analysis, and structured reporting to determine next steps.
