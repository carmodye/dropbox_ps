Below is a `README.md` file for your PowerShell script (`drop_box_pull.ps1`), which downloads files from specified Dropbox folders to a local directory. The README provides an overview, setup instructions, usage details, scheduling guidance for batch execution, and troubleshooting tips, tailored to your setup (e.g., `.env` file, `D:\LocalDropboxFiles`, machine shutdowns at night/weekends). It’s written in Markdown for clarity and assumes the script is located in `D:\code\dropbox_ps`.

---

# Dropbox File Download Script

This PowerShell script (`drop_box_pull.ps1`) downloads files from specified Dropbox folders to a local directory, preserving the folder structure. It uses the Dropbox API to authenticate via OAuth, list files recursively, and download them to a specified local path. The script is designed for automation, supports a `.env` file for configuration, and includes error handling, retry logic, and file existence checks.

## Features

- Downloads files from Dropbox folders listed in `C:\DropboxFolders.txt` to `D:\LocalDropboxFiles`.
- Preserves Dropbox folder structure (e.g., `/Apps/another_folder/file.docx` → `D:\LocalDropboxFiles\Apps\another_folder\file.docx`).
- Uses OAuth with refresh tokens for secure, persistent authentication.
- Externalizes configuration in a `.env` file for easy updates.
- Skips existing files to avoid duplicates and validates file existence in Dropbox.
- Includes retry logic for transient errors (e.g., network issues).
- Supports batch file execution and scheduling via Windows Task Scheduler.
- Handles machine shutdowns at night and weekends via scheduled runs.

## Prerequisites

- **PowerShell**: Windows PowerShell 5.1 or PowerShell Core 7+ (included in Windows 11).
- **Dropbox App**: Create an app in the [Dropbox App Console](https://www.dropbox.com/developers/apps) with:
  - Scopes: `files.content.read`, `files.metadata.read`.
  - Redirect URI: `http://localhost:8080`.
- **Write Permissions**: Access to write to `D:\LocalDropboxFiles` and read `C:\DropboxFolders.txt`.
- **Network Access**: Internet connection during script execution.

## Setup

1. **Clone or Save the Script**:

   - Save `drop_box_pull.ps1` to `D:\code\dropbox_ps\drop_box_pull.ps1`.

2. **Create `.env` File**:

   - Create `D:\code\dropbox_ps\.env` with the following content:
     ```env
     CLIENT_ID=your_client_id
     CLIENT_SECRET=your_client_secret
     REDIRECT_URI=http://localhost:8080
     FOLDERS_FILE=C:\DropboxFolders.txt
     CREDENTIAL_FILE=%USERPROFILE%\DropboxCredential.xml
     LOCAL_BASE_PATH=D:\LocalDropboxFiles
     ```
   - Replace `your_client_id` and `your_client_secret` with values from the Dropbox App Console (Settings tab).
   - Ensure `REDIRECT_URI` matches the App Console.
   - `FOLDERS_FILE` should point to your folder list file.
   - `CREDENTIAL_FILE` uses `%USERPROFILE%` to resolve to the user’s profile directory (e.g., `C:\Users\YourUsername\DropboxCredential.xml`).
   - `LOCAL_BASE_PATH` specifies the output directory.

3. **Create `C:\DropboxFolders.txt`**:

   - List Dropbox folder paths (one per line, starting with `/`):
     ```
     /Apps/another_folder
     /Apps/rcbm_scan
     /Apps/rcbm_scan2
     ```
   - Ensure paths exist in your Dropbox account and are accessible.

4. **Create Batch File (Optional)**:
   - For batch execution, create `D:\code\dropbox_ps\run_dropbox_pull.bat`:
     ```batch
     @echo off
     ECHO Running Dropbox pull script...
     powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\code\dropbox_ps\drop_box_pull.ps1"
     IF %ERRORLEVEL% NEQ 0 (
         ECHO Error: PowerShell script failed with exit code %ERRORLEVEL%.
         EXIT /B %ERRORLEVEL%
     )
     ECHO Script completed successfully.
     EXIT /B 0
     ```

## Usage

### Manual Execution

1. Open PowerShell as Administrator:
   ```powershell
   Start-Process powershell -Verb RunAs
   ```
2. Run the script:
   ```powershell
   cd D:\code\dropbox_ps
   .\drop_box_pull.ps1
   ```
3. If prompted, authorize the app in your browser (first run only). The script stores the refresh token in `%USERPROFILE%\DropboxCredential.xml` for subsequent runs.
4. Files will download to `D:\LocalDropboxFiles`, preserving the Dropbox folder structure.

### Batch Execution

Run the batch file:

```cmd
cd D:\code\dropbox_ps
run_dropbox_pull.bat
```

### Scheduled Execution

To account for machine shutdowns at night and weekends, schedule the script to run during operational hours (e.g., weekdays 9 AM–5 PM) using Windows Task Scheduler:

1. Open Task Scheduler (`taskschd.msc`).
2. Create a Task:
   - **General**:
     - Name: `DropboxPullScript`
     - Check “Run whether user is logged on or not” and “Run with highest privileges”.
   - **Triggers**:
     - New > On a schedule > Daily.
     - Start: `9:00 AM`, Repeat every: `1 hour`, Duration: `8 hours`.
     - Enabled: Checked.
   - **Actions**:
     - New > Start a program > `D:\code\dropbox_ps\run_dropbox_pull.bat`.
   - **Conditions**:
     - Uncheck “Start only if on AC power” (if on a laptop).
     - Optional: Check “Wake the computer to run this task”.
   - **Settings**:
     - Check “Allow task to be run on demand” and “Restart if the task fails” (3 times, 5-minute interval).
     - Set “If the task is already running”: “Do not start a new instance”.
3. Save with admin credentials.

## Expected Output

```
Listing files in '/Apps/another_folder'...
Found folder: /Apps/another_folder
Downloading '/Apps/another_folder/25.09.05 August Meeting Minutes.docx' to 'D:\LocalDropboxFiles\Apps\another_folder\25.09.05 August Meeting Minutes.docx' ...
Sanitized local path: D:\LocalDropboxFiles\Apps\another_folder\25.09.05 August Meeting Minutes.docx
Downloaded: /Apps/another_folder/25.09.05 August Meeting Minutes.docx to D:\LocalDropboxFiles\Apps\another_folder\25.09.05 August Meeting Minutes.docx
```

## Troubleshooting

1. **.env File Issues**:

   - Ensure `D:\code\dropbox_ps\.env` exists and has no typos or extra spaces.
   - Verify `CLIENT_ID` and `CLIENT_SECRET` are correct (from Dropbox App Console).

2. **Authentication Errors**:

   - If authentication fails, delete the credential file and reauthorize:
     ```powershell
     Remove-Item "$env:USERPROFILE\DropboxCredential.xml" -ErrorAction SilentlyContinue
     ```
   - Confirm `files.content.read` and `files.metadata.read` scopes are enabled in the App Console.

3. **File Download Issues**:

   - Check `C:\DropboxFolders.txt` for valid paths (e.g., `/Apps/another_folder`).
   - Verify the file exists in Dropbox using the API Explorer (`/2/files/get_metadata`):
     - `path`: `/Apps/another_folder/25.09.05 August Meeting Minutes.docx`
     - Headers: `Authorization: Bearer <access_token>`, `Content-Type: application/json`
   - Check for errors like `path/not_found` or `path/restricted_content`.

4. **Path Issues**:

   - Confirm write permissions to `D:\LocalDropboxFiles`.
   - Verify files save to the correct directory (e.g., `D:\LocalDropboxFiles\Apps\another_folder`).

5. **Scheduled Task Issues**:

   - Check Task Scheduler’s “History” tab for errors.
   - Ensure the task runs under an account with permissions to `D:\LocalDropboxFiles` and `C:\DropboxFolders.txt`.
   - Test manually: Right-click the task and select “Run”.

6. **Shutdown Conflicts**:
   - The script skips existing files (`Test-Path`) to handle interruptions from shutdowns.
   - Adjust the Task Scheduler trigger to match operational hours (e.g., 7 AM–3 PM) if needed.

## Enhancements

- **Incremental Downloads**: Add logic to download only new/modified files based on `client_modified` timestamps.
- **File Type Filtering**: Filter specific file types (e.g., `.docx`):
  ```powershell
  if ($Entry.'.tag' -eq 'file' -and $Entry.path_display -like '*.docx') { ... }
  ```
- **Logging**: Add logging to a file:
  ```powershell
  Start-Transcript -Path "D:\code\dropbox_ps\log.txt" -Append
  # Main script
  Stop-Transcript
  ```

## Security Notes

- Store `.env` securely and exclude it from version control (e.g., add `.env` to `.gitignore`).
- The refresh token in `%USERPROFILE%\DropboxCredential.xml` is encrypted with Windows DPAPI, accessible only to the user who created it.

## License

This script is provided as-is for personal use. Modify and distribute as needed, but ensure compliance with Dropbox API terms.

---

### Saving the README

- Save this as `D:\code\dropbox_ps\README.md`.
- If you use version control (e.g., Git), commit the README alongside `drop_box_pull.ps1` and `run_dropbox_pull.bat`, but exclude `.env`.

### Verification

- Ensure `D:\code\dropbox_ps\.env` is correctly set up (as shown above).
- Test the batch file:
  ```cmd
  cd D:\code\dropbox_ps
  run_dropbox_pull.bat
  ```
- Verify files download to `D:\LocalDropboxFiles\Apps\another_folder`.
- Set up the Task Scheduler task as described to handle shutdowns.

If you encounter issues or need additional features (e.g., incremental downloads, logging), please share the script’s output or specific requirements!
