# RSE_in_C
## Table of Contents
1. [Introduction](#introduction)
2. [Overview](#overview)
3. [Use Cases](#use-cases)
4. [Instructions for Use](#instructions-for-use)
5. [Disclaimers and Limitations](#disclaimers-and-limitations)
6. [Conclusion](#conclusion)

## Introduction
This document provides a detailed analysis of the backdoor and server code. The backdoor is designed to run on a Windows system and can be used to establish a reverse connection to a server, allowing remote command execution and keylogging. The server code is responsible for handling client connections and executing commands.

## Overview
### Backdoor Code
- **Purpose**: To create a backdoor that can capture keystrokes, hide the process, and provide remote command execution.
- **Components**:
  - Keylogger: Captures keystrokes and logs them to a file.
  - Hide Process: Hides the process from the task manager and console.
  - Persistence: Ensures the backdoor runs on boot by modifying the registry and creating scheduled tasks.
  - Run as Service: Registers the backdoor as a Windows service.
  - Shell Function: Handles remote command execution and communication with the server.

### Server Code
- **Purpose**: To handle client connections, execute commands, and manage multiple clients concurrently.
- **Components**:
  - Initialization: Sets up SSL/TLS and socket configurations.
  - Context Configuration: Configures the SSL context with certificates and keys.
  - Command Parsing: Parses commands received from clients and executes them.
  - Client Handling: Manages individual client connections in separate threads.
  - Main Function: Initializes the server and starts listening for client connections.

## Use Cases 
   - **Remote Access** : Allow remote access to a target system for administrative purposes.
   - **Keylogging** : Capture keystrokes to gather sensitive information.
   - **Persistence** : Ensure the backdoor runs on boot to maintain access.

## Instructions for Use 

1. **Compile the Code** : 
    - Compile the backdoor code on a Windows system.
    ```
        i686 -w64 -mingw32 -gcc -o [backdoor.exe] backdoor.c -lwsock32 -lwininet
    ```
    - Compile the server code on a Linux system.
         

2. **Set Up the Server** : 
    - Generate SSL certificates and keys using OpenSSL.
    - Start the server on the specified port (e.g., 50004).
         

3. **Deploy the Backdoor** : 
    - Distribute the compiled backdoor executable to the target system.
    - Run the backdoor on the target system.
         

4. **Connect to the Server** : 
    - Use the server to connect to the backdoor and execute commands.
         
     
## Disclaimers and Limitations 

   -  **Legal Warning** : This code is provided for educational purposes only. Using it without explicit permission is illegal and unethical.
   - **Security Risks** : The backdoor can be detected by security software and may compromise system security.
    Ethical Considerations : Always obtain proper authorization before using this code on any system.

## Conclusion 

This document provides a detailed analysis of the backdoor and server code. The backdoor is designed to capture keystrokes, hide the process, and provide remote command execution. The server code handles client connections and manages multiple clients concurrently. Both codes should be used responsibly and ethically. 


## Commands: 
- **q**: Exits the program.
- **keylog_start**: Starts keylogger.
- **cd:** Change directory.
- **persist**: Establish persistence mode.
- **run_as_service**: Run the shell as a windows service.

- **NB**: 
   - The remaining commands are the default windows shell commands
   - Use this project with caution. You are responsible for your actions!
