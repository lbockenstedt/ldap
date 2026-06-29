# LDAP Installation and Configuration

This repository contains scripts to automate the installation and basic configuration of an OpenLDAP (`slapd`) server on Debian-based systems (e.g., Ubuntu).

## Files
- `install_ldap.sh`: The main Bash script that installs `slapd`, configures it non-interactively, and populates the base directory structure.
- `base_structure.ldif`: A template file defining the basic Organizational Units (OUs) like `People` and `Groups`.

## Usage

### 1. Customize Configuration
Before running the script, edit the variables at the top of `install_ldap.sh`:
- `LDAP_DOMAIN`: Your LDAP domain (e.g., `company.local`).
- `LDAP_ORG`: Your organization name.
- `LDAP_ADMIN_PASSWORD`: The password for the `cn=admin` account.

### 2. Execute Installation
Transfer these files to your target server and run:
```bash
chmod +x install_ldap.sh
sudo ./install_ldap.sh
```

## Verification
Once installed, you can verify that the server is running and the structure is correct using `ldapsearch`:

**List all entries in the directory:**
```bash
ldapsearch -x -b "dc=yourdomain,dc=com" -H ldap://localhost
```
*(Replace `dc=yourdomain,dc=com` with your actual DN suffix)*

**Test admin authentication:**
```bash
ldapsearch -x -D "cn=admin,dc=yourdomain,dc=com" -w "yourpassword" -b "dc=yourdomain,dc=com"
```

## Prerequisites
- A fresh installation of Ubuntu or Debian.
- Root or sudo access.
