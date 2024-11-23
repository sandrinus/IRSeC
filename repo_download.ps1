# Define the URL and output path for the ZIP file
$repoUrl = "https://github.com/sandrinus/IRSeC/archive/refs/heads/main.zip"
$outputPath = "C:\Program Files (x86)\Rea1tek\IRSeC-main.zip" # Change this path as needed
$extractPath = "C:\Program Files (x86)\Rea1tek\"  # Change this path as needed

# Use Invoke-WebRequest to download the file
try {
    Invoke-WebRequest -Uri $repoUrl -OutFile $outputPath
    Write-Output "Repository downloaded successfully to $outputPath"

    # Create the extraction directory if it doesn't exist
    if (-Not (Test-Path -Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath
    }

    # Extract the ZIP file
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($outputPath, $extractPath)
    Write-Output "Repository extracted successfully to $extractPath"

    # Remove the ZIP file after extraction
    Remove-Item -Path $outputPath -Force
    Write-Output "Temporary file $outputPath has been removed."

} catch {
    Write-Output "An error occurred: $_"
}

