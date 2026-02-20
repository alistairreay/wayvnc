# wayvnc (macOS Screen Sharing Fork)

> If this fork helped you, consider supporting development:
> **[Buy me a coffee on Ko-fi](https://ko-fi.com/alistairreay)**

## Fork Overview
This is a fork of [wayvnc](https://github.com/any1/wayvnc) that adds
**macOS Screen Sharing.app** compatibility. Connect to your Wayland desktop
from a Mac using the built-in Screen Sharing app -- no third-party VNC client
needed.

### What's different from upstream?
 * **Legacy VNC Authentication** -- macOS Screen Sharing only supports VNC Auth
   (RFB security type 2). This fork adds opt-in support via
   `enable_vnc_auth=true` in the config file.
 * Uses the companion [neatvnc fork](https://github.com/alistairreay/neatvnc)
   which adds RFB 3.3 support, VNC Auth, and a CPIXEL encoding fix.

### Quick Start (macOS Screen Sharing)

1. **Build** (see build instructions below):
   ```
   git clone https://github.com/alistairreay/wayvnc.git
   git clone https://github.com/alistairreay/neatvnc.git
   git clone https://github.com/any1/aml.git

   mkdir wayvnc/subprojects
   cd wayvnc/subprojects
   ln -s ../../neatvnc .
   ln -s ../../aml .
   cd -

   mkdir neatvnc/subprojects
   cd neatvnc/subprojects
   ln -s ../../aml .
   cd -

   cd wayvnc
   meson setup build
   ninja -C build
   ```

2. **Configure** (`~/.config/wayvnc/config`):
   ```
   address=0.0.0.0
   enable_vnc_auth=true
   vnc_password=your_password_here
   ```

3. **Run** (e.g. on a headless Hyprland output):
   ```
   wayvnc -o HEADLESS-1
   ```

4. **Connect** from macOS: open Screen Sharing.app (or Cmd+K in Finder) and
   enter `vnc://<your-linux-ip>:5900`.

### HiDPI / Retina Setup
For a crisp image on Retina Macs, set your headless output to match the Mac's
**native** (physical) resolution with 2x scaling. For example, for a 16"
MacBook Pro (3456x2234 native):

```
# Hyprland example
hyprctl keyword monitor HEADLESS-1,3456x2234,0x0,2
```

Then in Screen Sharing, go to **View > Turn Scaling On**. The 2:1 scale ratio
maps each VNC pixel to exactly one physical pixel on the Retina display.

| Mac Model | Native Resolution | Hyprland Config |
|---|---|---|
| MacBook Air 13" (M1/M2) | 2560x1664 | `HEADLESS-1,2560x1664,0x0,2` |
| MacBook Air 15" (M2/M3) | 2880x1864 | `HEADLESS-1,2880x1864,0x0,2` |
| MacBook Pro 14" | 3024x1964 | `HEADLESS-1,3024x1964,0x0,2` |
| MacBook Pro 16" | 3456x2234 | `HEADLESS-1,3456x2234,0x0,2` |
| iMac 24" | 4480x2520 | `HEADLESS-1,4480x2520,0x0,2` |
| Non-Retina / 1080p | 1920x1080 | `HEADLESS-1,1920x1080,0x0,1` |

### Security Warning
VNC Authentication (type 2) uses a weak DES-based challenge-response scheme.
The password is limited to 8 characters, and traffic is unencrypted. This is
adequate for a trusted local network but **should not be used over the
internet**. For remote access, use an SSH tunnel:
```
ssh -L 5900:localhost:5900 user@your-linux-host
```
Then connect Screen Sharing to `vnc://localhost:5900`.

### Known Limitations
 * **No Dynamic Resolution** -- macOS Screen Sharing's Dynamic Resolution
   feature requires Apple's proprietary High Performance screen sharing mode
   (Apple Silicon + macOS Sonoma 14+). It is not a VNC protocol feature and
   cannot be implemented by third-party servers.
 * **Password limited to 8 characters** -- This is a limitation of VNC Auth
   (type 2), not this fork.

---

## Introduction
This is a VNC server for wlroots-based Wayland compositors (:no_entry: Gnome,
KDE and Weston are **not** supported). It attaches to a running Wayland session,
creates virtual input devices, and exposes a single display via the RFB
protocol. The Wayland session may be a headless one, so it is also possible
to run wayvnc without a physical display attached.

Please check the [FAQ](FAQ.md) for answers to common questions. For further
support, join the #wayvnc IRC channel on libera.chat, or ask your questions on the
GitHub [discussion forum](https://github.com/any1/wayvnc/discussions) for the
project.

## Building
### Runtime Dependencies
 * aml
 * drm
 * gbm (optional)
 * libxkbcommon
 * neatvnc
 * pam (optional)
 * pixman
 * jansson

### Build Dependencies
 * GCC
 * meson
 * ninja
 * pkg-config

#### For Arch Linux
```
pacman -S base-devel libglvnd libxkbcommon pixman gnutls jansson
```

#### For Fedora 37
```
dnf install -y meson gcc ninja-build pkg-config egl-wayland egl-wayland-devel \
	mesa-libEGL-devel mesa-libEGL libwayland-egl libglvnd-devel \
	libglvnd-core-devel libglvnd mesa-libGLES-devel mesa-libGLES \
	libxkbcommon-devel libxkbcommon libwayland-client \
	pam-devel pixman-devel libgbm-devel libdrm-devel scdoc \
	libavcodec-free-devel libavfilter-free-devel libavutil-free-devel \
	turbojpeg-devel	wayland-devel gnutls-devel jansson-devel
```

#### For Debian (unstable / testing)
```
apt build-dep wayvnc
```

#### For Ubuntu
```
apt install meson libdrm-dev libxkbcommon-dev libwlroots-dev libjansson-dev \
	libpam0g-dev libgnutls28-dev libavfilter-dev libavcodec-dev \
	libavutil-dev libturbojpeg0-dev scdoc
```

#### Additional build-time dependencies

The easiest way to satisfy the neatvnc and aml dependencies is to link to them
in the subprojects directory:
```
git clone https://github.com/any1/wayvnc.git
git clone https://github.com/any1/neatvnc.git
git clone https://github.com/any1/aml.git

mkdir wayvnc/subprojects
cd wayvnc/subprojects
ln -s ../../neatvnc .
ln -s ../../aml .
cd -

mkdir neatvnc/subprojects
cd neatvnc/subprojects
ln -s ../../aml .
cd -
```

### Configure and Build
```
meson build
ninja -C build
```

To run the unit tests:
```
meson test -C build
```

To run the [integration tests](test/integration/README.md):
```
./test/integration/integration.sh
```

## Running
Wayvnc can be run from the build directory like so:
```
./build/wayvnc
```

:radioactive: The server only accepts connections from localhost by default. To
accept connections via any interface, set the address to `0.0.0.0` like this:
```
./build/wayvnc 0.0.0.0
```

:warning: Do not do this on a public network or the internet without
user authentication enabled. The best way to protect your VNC connection is to
use SSH tunneling while listening on localhost, but users can also be
authenticated when connecting to wayvnc.

### Encryption & Authentication

#### VeNCrypt (TLS)
For TLS, you'll need a private X509 key and a certificate. A self-signed key
with a certificate can be generated like so:
```
cd ~/.config/wayvnc
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -sha384 \
	-days 3650 -nodes -keyout tls_key.pem -out tls_cert.pem \
	-subj /CN=localhost \
	-addext subjectAltName=DNS:localhost,DNS:localhost,IP:127.0.0.1
cd -
```
Replace `localhost` and `127.0.0.1` in the command above with your public facing
host name and IP address, respectively, or just keep them as is if you're
testing locally.

Create a config with the authentication info and load it using the `--config`
command line option or place it at the default location
`$HOME/.config/wayvnc/config`.
```
use_relative_paths=true
address=0.0.0.0
enable_auth=true
username=luser
password=p455w0rd
private_key_file=tls_key.pem
certificate_file=tls_cert.pem
```

#### RSA-AES
The RSA-AES security type combines RSA with AES in EAX mode to provide secure
authentication and encryption that's resilient to eavesdropping and MITM. Its
main weakness is that the user has to verify the server's credentials on first
use. Thereafter, the client software should warn the user if the server's
credentials change. It's a Trust on First Use (TOFU) scheme as employed by SSH.

For the RSA-AES to be enabled, you need to generate an RSA key. This can be
achieved like so:
```
ssh-keygen -m pem -f ~/.config/wayvnc/rsa_key.pem -t rsa -N ""
```

You also need to tell wayvnc where this file is located, by setting setting the
`rsa_private_key_file` configuration parameter:
```
use_relative_paths=true
address=0.0.0.0
enable_auth=true
username=luser
password=p455w0rd
rsa_private_key_file=rsa_key.pem
```

You may also add credentials for TLS in combination with RSA. The client will
choose.

#### VNC Authentication (Legacy -- macOS Screen Sharing)
For clients that only support classic VNC authentication (such as macOS Screen
Sharing.app), enable legacy VNC Auth in the config:
```
address=0.0.0.0
enable_vnc_auth=true
vnc_password=p455w0rd
```

This can be combined with VeNCrypt and RSA-AES -- the server will offer all
configured security types and the client will pick the one it supports.

:warning: VNC Auth uses a weak DES-based challenge-response and sends all
subsequent traffic unencrypted. Use only on trusted networks or via an SSH
tunnel.

### wayvncctl control socket

To facilitate runtime interaction and control, wayvnc opens a unix domain socket
at *$XDG_RUNTIME_DIR*/wayvncctl (or a fallback of /tmp/wayvncctl-*$UID*). A
client can connect and exchange json-formatted IPC messages to query and control
the running wayvnc instance.

Use the `wayvncctl` utility to interact with this control socket from the
command line.

See the `wayvnc(1)` manpage for an in-depth description of the IPC protocol and
the available commands, and `wayvncctl(1)` for more on the command line
interface.

There is also a handy event-loop mode that can be used to run commands when
various events occur in wayvnc. See
[examples/event-watcher](examples/event-watcher) for more details.
