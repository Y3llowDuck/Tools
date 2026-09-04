# Check Outbound Ports

A PowerShell script to test outbound TCP connectivity from your Windows machine. This script dynamically prompts the user to validate outbound communication to specific ports on a target server, helping troubleshoot network configurations and firewall rules.

## Features

- Dynamically prompts the user for:
  - Target server (IP address or hostname).
  - Number of ports to test.
  - Ports to check.
- Validates target server and port inputs.
- Uses PowerShell's built-in `Test-NetConnection` cmdlet for efficient and accurate testing.
- Provides clear results for each port: **open** or **blocked**.
- Includes instructions for simulating blocked ports using Windows Firewall rules.

## Prerequisites

- A Windows system with **PowerShell 5.1** or later installed.
- Optional: Administrator privileges for managing Windows Firewall rules, if we want to test blocked ports.

## Usage

1. Clone the repository:
   ```bash
   ## Cloning the repository.
   git clone https://github.com/Y3llowDuck/port_check_PowerShell.git
   ## Once cloned, we go to the location where the PowerShell script resides.
   ## Make sure you are able to execute PowerShell scripts.
   powershell -ExecutionPolicy Bypass -File .\check-outbound-ports.ps1
   ## Then execute :
   .\check-outbound-ports.ps1

Here’s an example of what running the script looks like:

![Script Output Example](https://github.com/Y3llowDuck/port_check_PowerShell/blob/main/Screenshot%202024-12-16%20at%201.16.51%20PM.png?raw=true)


