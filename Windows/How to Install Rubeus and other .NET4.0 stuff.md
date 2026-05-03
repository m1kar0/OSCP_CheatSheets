
## 1. Prepare the Targeting Pack (One-time fix)

```powershell
# Navigate to the folder
cd "C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0"

# Extract the zip you downloaded
Expand-Archive -Path "microsoft.netframework.referenceassemblies.net40.1.0.3.zip" -DestinationPath . -Force

# Copy the reference files
Copy-Item -Path "build\.NETFramework\v4.0\*" -Destination . -Recurse -Force

# Cleanup
Remove-Item "microsoft.netframework.referenceassemblies.net40.1.0.3.zip" -Force
Remove-Item "build" -Recurse -Force
````

## 2. Build Rubeus

PowerShell

```
# Go to Rubeus source
cd C:\Sandbox\Rubeus

# Clean + Build Release (Any CPU)
msbuild Rubeus.sln /t:Clean,Build /p:Configuration=Release /p:Platform="Any CPU" /m
```
