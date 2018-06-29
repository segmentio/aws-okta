# Windows Support

Documentation for getting `aws-okta` working with Windows.

Environments where aws-okta works under Windows basically fall into 2 categories: "normal" Windows and Windows Subsystem for Linux.  Note that your home directory in WSL and your home directory in "normal" Windows are not the same!  Changes you make in WSL will not be reflected outside of WSL and vice versa.

## "Normal" Windows

"Normal" Windows includes Windows shells/environments that execute Windows binaries and use the standard Windows filesystems available in Explorer.  `aws-okta` generally works fine here but `aws-okta` must be run in cmd.exe or PowerShell (not ISE).  Environments where `aws-okta login` and `aws-okta exec` are known to work include:

* cmd.exe
* PowerShell
* PowerShell ISE
* [Git BASH](https://gitforwindows.org/)

### Installation

1. Install [go for windows](https://golang.org/dl/) >= 1.10
2. From your favorite shell `go get github.com/segmentio/aws-okta`
3. Add `%USERPROFILE%\go\bin` to your PATH
4. From a cmd.exe shell run `aws-okta add` - some shells lack the required functionality for this command to work but cmd.exe is consistent
5. Follow the general instructions for configuring and using `aws-okta`
6. To update `go get -u github.com/segmentio/aws-okta`

## Windows Subsystem for Linux

`aws-okta` generally works fine in WSL as long as you're on Windows build >= 15093.  Windows builds earlier than this lack the console features required.  To find out what build of Windows you're on run the `winver` command.

The easiest way to install under WSL is to download the [latest release](https://github.com/segmentio/aws-okta/releases) Linux binary and put it somewhere in your path.

### Installation From Source

1. Install golang >= 1.10 - follow the instructions [here](https://github.com/golang/go/wiki/Ubuntu) if your WSL distribution does not natively include an appropriate version
2. `go get github.com/segmentio/aws-okta`
3. Add `~/go/bin` to your $PATH
4. Follow the general instructions for configuring and using `aws-okta`
5. To update `go get -u github.com/segmentio/aws-okta`
