# Packaging CozyGuard

This document describes how to build and package CozyGuard for Ubuntu.

## Prerequisites

Install the required packaging tools:

```bash
sudo apt update
sudo apt install -y build-essential devscripts debhelper dh-python python3-all python3-setuptools
```

## Building the Debian Package

1. Navigate to the project directory:

```bash
cd ~/Work/CozyGuard
```

2. Build the package:

```bash
debuild -us -uc
```

This will create the Debian package in the parent directory.

3. Install the package:

```bash
sudo dpkg -i ../cozyguard_0.1.0-1_all.deb
sudo apt-get install -f  # Install any missing dependencies
```

## Signing the Package

To sign the package for distribution:

1. Generate a GPG key if you don't have one:

```bash
gpg --gen-key
```

2. Build the signed package:

```bash
debuild -k<YOUR_KEY_ID>
```

3. Create a local repository:

```bash
mkdir -p ~/apt-repo/pool/main/c/cozyguard
cp ../cozyguard_0.1.0-1_all.deb ~/apt-repo/pool/main/c/cozyguard/
cd ~/apt-repo
dpkg-scanpackages pool/ > Packages
gzip -k Packages
apt-ftparchive release . > Release
gpg --clearsign -o InRelease Release
gpg -abs -o Release.gpg Release
```

4. Add the repository to your sources:

```bash
echo "deb [trusted=yes] file:$HOME/apt-repo ./" | sudo tee /etc/apt/sources.list.d/local.list
sudo apt update
```

Now you can install the package with:

```bash
sudo apt install cozyguard
```

## Publishing to a PPA (Ubuntu)

To publish to a Launchpad PPA:

1. Create a Launchpad account and set up a PPA
2. Configure your GPG key in Launchpad
3. Build the source package:

```bash
debuild -S
```

4. Upload to your PPA:

```bash
dput ppa:your-username/your-ppa ../cozyguard_0.1.0-1_source.changes
```
