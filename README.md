# Octelium packages

Signed APT and RPM repositories served from `https://packages.octelium.com`.

## Debian and Ubuntu

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/octelium.gpg https://packages.octelium.com/keys/octelium.gpg
sudo curl -fsSLo /etc/apt/sources.list.d/octelium.sources https://packages.octelium.com/deb/octelium.sources
sudo apt-get update && sudo apt-get install octelium
```

## Fedora, RHEL, CentOS, Rocky, Alma, Oracle and Amazon Linux

```sh
sudo curl -fsSLo /etc/yum.repos.d/octelium.repo https://packages.octelium.com/rpm/octelium.repo
sudo dnf install octelium
```

## openSUSE and SLES

```sh
sudo zypper addrepo https://packages.octelium.com/rpm/octelium.repo
sudo zypper install octelium
```

## Publishing

```sh
go run ./cmd/pkgrepo publish --storage r2://BUCKET --key awskms:KMS_KEY_ARN --sync
```

The signing key is an AWS KMS `SIGN_VERIFY` key. `RSA_4096` works on every distribution; `ECC_NIST_P256` is not supported by RHEL 8/9, Amazon Linux 2023, SLES 15 and older RPM distributions. Publishing needs `createrepo_c` and an `rpmsign` that supports the key type, such as the one in Fedora.
