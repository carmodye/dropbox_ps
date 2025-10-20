# Function to load variables from .env file
function Import-EnvFile {
    param ($EnvFilePath)
    $envVars = @{}
    if (-not (Test-Path $EnvFilePath)) {
        Write-Error ".env file not found at: $EnvFilePath"
        exit
    }
    Get-Content $EnvFilePath | ForEach-Object {
        $line = $_.Trim()
        if ($line -and $line -notmatch '^#') {
            $key, $value = $line -split '=', 2
            $key = $key.Trim()
            $value = $value.Trim()
            # Expand environment variables in the value (e.g., %USERPROFILE%)
            $value = [System.Environment]::ExpandEnvironmentVariables($value)
            $envVars[$key] = $value
        }
    }
    return $envVars
}

# Load variables from .env file
$envFile = Join-Path $PSScriptRoot ".env"
$envVars = Import-EnvFile -EnvFilePath $envFile

# Assign variables from .env
$ClientId = $envVars['CLIENT_ID']
$ClientSecret = $envVars['CLIENT_SECRET']
$RedirectUri = $envVars['REDIRECT_URI']
$FoldersFile = $envVars['FOLDERS_FILE']
$CredentialFile = $envVars['CREDENTIAL_FILE']
$LocalBasePath = $envVars['LOCAL_BASE_PATH']

# Load System.Web for query parsing and URL encoding
Add-Type -AssemblyName System.Web

# Function to start a local HTTP server to capture OAuth code
function Start-LocalHttpServer {
    param ($Port = 8080)
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$Port/")
    try {
        $listener.Start()
        Write-Host "Listening for OAuth callback on http://localhost:$Port ..."
        $context = $listener.GetContext()
        $url = $context.Request.Url
        Write-Host "Received callback URL: $url"
        $query = [System.Web.HttpUtility]::ParseQueryString($url.Query)
        $code = $query["code"]
        Write-Host "Parsed query parameters: $($query.AllKeys -join ', ')"
        if (-not $code) {
            throw "No authorization code found in callback URL. Query parameters: $($query.AllKeys -join ', ')"
        }
        Write-Host "Captured authorization code: $code"
        $context.Response.StatusCode = 200
        $context.Response.OutputStream.Write([System.Text.Encoding]::UTF8.GetBytes("Authorization received. You can close this window."), 0, 0)
        $context.Response.Close()
        return $code
    }
    catch {
        Write-Error "HTTP listener failed: $($_.Exception.Message)"
        throw
    }
    finally {
        $listener.Stop()
    }
}

# Function to get or refresh access token
function Get-DropboxAccessToken {
    param ($ClientId, $ClientSecret, $RedirectUri, $CredentialFile)

    if (-not $ClientId -or $ClientId -eq "YOUR_CLIENT_ID") {
        throw "ClientId is not set. Update CLIENT_ID in .env file."
    }
    if (-not $ClientSecret -or $ClientSecret -eq "YOUR_CLIENT_SECRET") {
        throw "ClientSecret is not set. Update CLIENT_SECRET in .env file."
    }
    if (-not $RedirectUri) {
        throw "RedirectUri is not set. Update REDIRECT_URI in .env file."
    }

    if (Test-Path $CredentialFile) {
        try {
            $credential = Import-Clixml -Path $CredentialFile
            $refreshToken = $credential.GetNetworkCredential().Password
            $body = @{
                grant_type    = "refresh_token"
                refresh_token = $refreshToken
                client_id     = $ClientId
                client_secret = $ClientSecret
            }
            $formBody = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join "&"
            Write-Host "Refreshing token with body: $formBody"
            try {
                $response = Invoke-RestMethod -Uri "https://api.dropboxapi.com/oauth2/token" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $formBody
                return $response.access_token
            }
            catch {
                Write-Warning "Failed to refresh token: $($_.Exception.Message)"
                if ($_.ErrorDetails.Message) {
                    Write-Warning "Refresh token error details: $($_.ErrorDetails.Message)"
                }
                elseif ($_.Exception.Response) {
                    $responseStream = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    Write-Warning "Refresh token error details: $responseStream"
                }
                Write-Warning "Attempting new authorization."
                Remove-Item -Path $CredentialFile -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning "Failed to read credential file: $($_.Exception.Message)"
            Remove-Item -Path $CredentialFile -ErrorAction SilentlyContinue
        }
    }

    $authUrl = "https://www.dropbox.com/oauth2/authorize?client_id=$ClientId&response_type=code&redirect_uri=$RedirectUri&token_access_type=offline"
    Write-Host "Opening browser for Dropbox authorization: $authUrl"
    Start-Process $authUrl

    $code = Start-LocalHttpServer -Port 8080
    Write-Host "Using authorization code: $code"

    $body = @{
        code          = $code
        grant_type    = "authorization_code"
        client_id     = $ClientId
        client_secret = $ClientSecret
        redirect_uri  = $RedirectUri
    }
    $formBody = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join "&"
    Write-Host "Token exchange request body: $formBody"
    Write-Host "Token exchange headers: Content-Type: application/x-www-form-urlencoded"
    try {
        $response = Invoke-RestMethod -Uri "https://api.dropboxapi.com/oauth2/token" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $formBody
        $securePassword = ConvertTo-SecureString $response.refresh_token -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("DropboxRefreshToken", $securePassword)
        $credential | Export-Clixml -Path $CredentialFile
        $acl = Get-Acl $CredentialFile
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $CredentialFile -AclObject $acl
        Write-Host "Successfully stored refresh token in $CredentialFile"
        return $response.access_token
    }
    catch {
        Write-Error "Token exchange failed: $($_.Exception.Message)"
        if ($_.ErrorDetails.Message) {
            Write-Error "Token exchange error details: $($_.ErrorDetails.Message)"
        }
        elseif ($_.Exception.Response) {
            $responseStream = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Write-Error "Token exchange error details: $responseStream"
        }
        throw
    }
}

# Function to check if a file exists in Dropbox
function Test-DropboxFile {
    param ($AccessToken, $DropboxPath)
    $Body = @{
        path = $DropboxPath
    } | ConvertTo-Json -Compress
    $Headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    $Uri = "https://api.dropboxapi.com/2/files/get_metadata"

    try {
        $Response = Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Body
        return $Response.'.tag' -eq 'file'
    }
    catch {
        Write-Warning "Failed to check metadata for '$DropboxPath': $($_.Exception.Message)"
        if ($_.ErrorDetails.Message) {
            Write-Warning "Metadata error details: $($_.ErrorDetails.Message)"
        }
        elseif ($_.Exception.Response) {
            $responseStream = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Write-Warning "Metadata error details: $responseStream"
        }
        return $false
    }
}

# Function to download a file from Dropbox
function Download-DropboxFile {
    param ($AccessToken, $DropboxPath, $LocalPath)
    # Ensure proper JSON encoding for Dropbox-API-Arg header
    $EncodedPath = [System.Web.HttpUtility]::UrlEncode($DropboxPath)
    $Body = @{
        path = $DropboxPath
    } | ConvertTo-Json -Compress
    $Headers = @{
        "Authorization"   = "Bearer $AccessToken"
        "Dropbox-API-Arg" = $Body
        "Content-Type"    = "application/octet-stream"
    }
    Write-Host "Downloading '$DropboxPath' to '$LocalPath' with Dropbox-API-Arg: $Body (Encoded Path: $EncodedPath)"
    
    try {
        # Validate file existence
        if (-not (Test-DropboxFile -AccessToken $AccessToken -DropboxPath $DropboxPath)) {
            Write-Warning "Skipping '$DropboxPath': File does not exist or is inaccessible in Dropbox"
            return
        }
        # Skip if file already exists locally
        if (Test-Path $LocalPath) {
            Write-Host "Skipping '$DropboxPath': File already exists at $LocalPath"
            return
        }
        # Create parent directory if it doesn't exist
        $ParentDir = Split-Path $LocalPath -Parent
        if (-not (Test-Path $ParentDir)) {
            New-Item -Path $ParentDir -ItemType Directory -Force | Out-Null
            Write-Host "Created directory: $ParentDir"
        }
        # Sanitize only the file name (not the full path) for Windows
        $FileName = Split-Path $LocalPath -Leaf
        $SanitizedFileName = $FileName -replace '[<>:"|?*]', '_'
        $SanitizedLocalPath = Join-Path (Split-Path $LocalPath -Parent) $SanitizedFileName
        Write-Host "Sanitized local path: $SanitizedLocalPath"
        # Download file with retry logic
        $maxRetries = 3
        $retryCount = 0
        $success = $false
        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/download" -Method Post -Headers $Headers -OutFile $SanitizedLocalPath
                Write-Host "Downloaded: $DropboxPath to $SanitizedLocalPath"
                $success = $true
            }
            catch {
                $retryCount++
                Write-Warning "Attempt $retryCount of $maxRetries failed for '$DropboxPath': $($_.Exception.Message)"
                if ($_.ErrorDetails.Message) {
                    Write-Warning "Download error details: $($_.ErrorDetails.Message)"
                }
                elseif ($_.Exception.Response) {
                    $responseStream = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    Write-Warning "Download error details: $responseStream"
                }
                if ($retryCount -lt $maxRetries) {
                    Write-Host "Retrying in 5 seconds..."
                    Start-Sleep -Seconds 5
                }
            }
        }
        if (-not $success) {
            Write-Error "Failed to download '$DropboxPath' after $maxRetries attempts"
        }
    }
    catch {
        Write-Error "Failed to download '$DropboxPath': $($_.Exception.Message)"
        if ($_.ErrorDetails.Message) {
            Write-Error "Download error details: $($_.ErrorDetails.Message)"
        }
        elseif ($_.Exception.Response) {
            $responseStream = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Write-Error "Download error details: $responseStream"
        }
    }
}

function List-AndDownload-DropboxFolder {
    param ($AccessToken, $FolderPath, $LocalBasePath)

    $Headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $ListUri = "https://api.dropboxapi.com/2/files/list_folder"
    $DeleteUri = "https://api.dropboxapi.com/2/files/delete_v2"

    $Body = @{
        path                                = $FolderPath
        recursive                           = $true
        include_media_info                  = $false
        include_deleted                     = $false
        include_has_explicit_shared_members = $false
        include_mounted_folders             = $true
    } | ConvertTo-Json

    try {
        Write-Host "`nListing files in '$FolderPath'..."
        $Response = Invoke-RestMethod -Uri $ListUri -Method Post -Headers $Headers -Body $Body

        function DownloadAndDelete {
            param ($DropboxPath, $LocalPath)

            try {
                Download-DropboxFile -AccessToken $AccessToken -DropboxPath $DropboxPath -LocalPath $LocalPath

                if (Test-Path $LocalPath) {
                    Write-Host "Downloaded: $DropboxPath → $LocalPath"
                    $DeleteBody = @{ path = $DropboxPath } | ConvertTo-Json
                    Invoke-RestMethod -Uri $DeleteUri -Method Post -Headers $Headers -Body $DeleteBody
                    Write-Host "Deleted from Dropbox: $DropboxPath"
                } else {
                    Write-Warning "Download failed or file missing: $LocalPath"
                }
            } catch {
                Write-Error "Error downloading or deleting '$DropboxPath': $($_.Exception.Message)"
            }
        }

        foreach ($Entry in $Response.entries) {
            if ($Entry.'.tag' -eq 'file') {
                $DropboxPath = $Entry.path_display
                $RelativePath = $DropboxPath.TrimStart('/')
                $LocalPath = Join-Path $LocalBasePath $RelativePath
                DownloadAndDelete -DropboxPath $DropboxPath -LocalPath $LocalPath
            } elseif ($Entry.'.tag' -eq 'folder') {
                Write-Host "Found folder: $($Entry.path_display)"
            }
        }

        while ($Response.has_more) {
            $Body = @{ cursor = $Response.cursor } | ConvertTo-Json
            $Response = Invoke-RestMethod -Uri "$ListUri/continue" -Method Post -Headers $Headers -Body $Body

            foreach ($Entry in $Response.entries) {
                if ($Entry.'.tag' -eq 'file') {
                    $DropboxPath = $Entry.path_display
                    $RelativePath = $DropboxPath.TrimStart('/')
                    $LocalPath = Join-Path $LocalBasePath $RelativePath
                    DownloadAndDelete -DropboxPath $DropboxPath -LocalPath $LocalPath
                } elseif ($Entry.'.tag' -eq 'folder') {
                    Write-Host "Found folder: $($Entry.path_display)"
                }
            }
        }
    } catch {
        Write-Error "Failed to list folder '$FolderPath': $($_.Exception.Message)"
        if ($_.ErrorDetails.Message) {
            Write-Error "List folder error details: $($_.ErrorDetails.Message)"
        } elseif ($_.Exception.Response) {
            $responseStream = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Write-Error "List folder error details: $responseStream"
        }
    }
}

# Main script
try {
    # Validate parameters
    if (-not $ClientId) {
        Write-Error "ClientId is not set. Update CLIENT_ID in .env file."
        exit
    }
    if (-not $ClientSecret) {
        Write-Error "ClientSecret is not set. Update CLIENT_SECRET in .env file."
        exit
    }
    if (-not (Test-Path $FoldersFile)) {
        Write-Error "Folder list file not found: $FoldersFile"
        exit
    }

    # Create local base directory if it doesn't exist
    if (-not (Test-Path $LocalBasePath)) {
        New-Item -Path $LocalBasePath -ItemType Directory -Force | Out-Null
        Write-Host "Created local base directory: $LocalBasePath"
    }

    # Get access token via OAuth
    $AccessToken = Get-DropboxAccessToken -ClientId $ClientId -ClientSecret $ClientSecret -RedirectUri $RedirectUri -CredentialFile $CredentialFile

    # Read folder paths from text file
    $Folders = Get-Content $FoldersFile | Where-Object { $_ -match "^/.*" }  # Ensure paths start with /
    if (-not $Folders) {
        Write-Error "No valid folder paths found in $FoldersFile"
        exit
    }

    # List and download files for each folder
    foreach ($Folder in $Folders) {
        List-AndDownload-DropboxFolder -AccessToken $AccessToken -FolderPath $Folder.Trim() -LocalBasePath $LocalBasePath
    }
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
}
