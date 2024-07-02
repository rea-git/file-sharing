# file-sharing
for default: 
* username - admin
* password - password
To run the application following to be installed in your computer - install required packages.
* python 3
* pip install bcrypt cryptography
* sudo apt-get install python3-tk
* pip install bcrypt cryptography
* sudo apt-get update
* sudo apt-get install python3 python3-tk
### Project Summary
user-friendly file-sharing application built using Python and Tkinter. It provides a secure way to upload, download, view, and delete files, with the following key functionalities:

1. **User Authentication**: Secure login system using hashed passwords with bcrypt.
2. **File Encryption**: Files are encrypted with Fernet symmetric encryption before being uploaded.
3. **File Management**: Users can view the list of uploaded files, download decrypted files, and delete files.
4. **Enhanced UI**: Modern, themed widgets and an organized layout for better user experience.

### Key Features

- **Upload Files**: Encrypt and upload files to a designated server directory.
- **Download Files**: Decrypt and download files from the server.
- **View Files**: Display a list of all encrypted files available on the server.
- **Delete Files**: Remove files from the server securely.
- **User Authentication**: Ensure that only authorized users can access the file management features.

This application is suitable for securely sharing and managing files in a controlled environment.
