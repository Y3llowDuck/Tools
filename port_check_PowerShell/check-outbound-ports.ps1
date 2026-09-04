# Function to validate if the target is a valid IP or hostname
function Validate-Target {
    param (
        [string]$Target
    )
    # Check if the target is a valid IP address
    if ($Target -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
        return $true  # Valid IP
    }
    # Check if the target is a valid hostname
    if ($Target -match '^(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$') {
        return $true  # Valid hostname
    }
    return $false  # Invalid target
}

# Function to validate port numbers
function Validate-Port {
    param (
        [string]$Port
    )
    # Ensure the port is numeric and between 1 and 65535
    if ($Port -match '^\d+$' -and [int]$Port -ge 1 -and [int]$Port -le 65535) {
        return $true
    }
    return $false
}

# Prompt user for the target server
$Target = Read-Host "Enter the target server (default: portquiz.net)"
if ([string]::IsNullOrWhiteSpace($Target)) {
    $Target = "portquiz.net"  # Default target
}

# Validate the target server
if (-not (Validate-Target -Target $Target)) {
    Write-Host "Invalid target server. Please provide a valid IP address or hostname." -ForegroundColor Red
    exit
}

# Ask user how many ports to check
$NumPorts = Read-Host "How many ports would you like to check?"
if (-not ($NumPorts -as [int]) -or $NumPorts -lt 1) {
    Write-Host "Invalid number of ports. Please provide a positive integer." -ForegroundColor Red
    exit
}

# Collect port numbers from the user
$Ports = @()
for ($i = 1; $i -le $NumPorts; $i++) {
    $Port = Read-Host "Enter port number $i"
    if (-not (Validate-Port -Port $Port)) {
        Write-Host "Invalid port number: $Port. Please enter a valid port (1-65535)." -ForegroundColor Red
        exit
    }
    $Ports += [int]$Port
}

# Function to check outbound connectivity for a given port
function Check-Port {
    param (
        [string]$Target,
        [int]$Port
    )
    try {
        $Connection = Test-NetConnection -ComputerName $Target -Port $Port -WarningAction SilentlyContinue
        if ($Connection.TcpTestSucceeded) {
            Write-Host "Outbound connection successful on port $Port" -ForegroundColor Green
        } else {
            Write-Host "Outbound connection blocked on port $Port" -ForegroundColor Red
        }
    } catch {
        Write-Host "Error testing port $Port. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main script loop
Write-Host "Checking outbound connectivity to $Target..." -ForegroundColor Cyan
foreach ($Port in $Ports) {
    Check-Port -Target $Target -Port $Port
}

Write-Host "All ports checked!" -ForegroundColor Cyan

# --- HOW TO SIMULATE A BLOCKED PORT ON WINDOWS ---
# To simulate blocking a port using Windows Firewall:
# 1. Open PowerShell as Administrator.
# 2. Use the following command to block outbound traffic on a specific port:
#    New-NetFirewallRule -DisplayName "Block Outbound Port <PORT>" -Direction Outbound -Protocol TCP -LocalPort <PORT> -Action Block
#    Example: To block port 80:
#    New-NetFirewallRule -DisplayName "Block Outbound Port 80" -Direction Outbound -Protocol TCP -LocalPort 80 -Action Block
#
# 3. To verify the rule was created:
#    Get-NetFirewallRule -DisplayName "Block Outbound Port 80"
#
# 4. To remove the rule and unblock the port:
#    Remove-NetFirewallRule -DisplayName "Block Outbound Port 80"
# ---------------------------------------------------
