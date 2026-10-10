# Windows setup

## Install and check

From the repository in PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
ato doctor
```

The gateway uses mitmdump from the current Python environment when available. Doctor reports CA trust and occupied ports. Choose an available port with `ato start --proxy-port 8081`; do not stop unrelated services to free 8080.

## Browse through the explicit proxy

Start the gateway in one terminal:

```powershell
ato start --proxy-port 8081
```

In another PowerShell terminal, launch Edge with a separate profile and proxy:

```powershell
$atoEdge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
& $atoEdge "--user-data-dir=$env:LOCALAPPDATA\ATO\BrowserProfile" "--proxy-server=http://127.0.0.1:8081" "https://www.google.com"
```

Adjust the executable path if Edge is installed elsewhere. Chrome accepts the same proxy/profile arguments. A separate profile is necessary because an already running browser may ignore new launch flags. The gateway does not change the system proxy. Terminal proxy environment variables alone do not route Chrome/Edge.

Open http://127.0.0.1:8765/ to inspect traffic. Without CA trust, HTTPS passes through encrypted by default, preserving the site's certificate. Only TLS destination metadata is available until decryption is configured.

## Enable HTTPS payload capture

Run:

```powershell
ato cert
```

Review the displayed public certificate path and SHA256 fingerprint. For Chrome/Edge, the command it prints installs this local CA in your current user's Trusted Root store, for example:

```powershell
certutil -user -addstore Root "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
```

If `ATO_MITMPROXY_CONFDIR` is set, use the exact path printed by `ato cert`. Trusting this CA permits certificates issued by this local mitmproxy installation to be accepted by clients using that trust store. ATO only prints the command; it does not install trust automatically.

Close and restart the capture browser and gateway:

```powershell
ato start --proxy-port 8081 --https decrypt
```

The `ato cert` output also prints the exact `certutil -user -delstore Root <thumbprint>` command to remove this certificate afterward. Remove only the reviewed certificate by its thumbprint.

Firefox, Python/requests/httpx, Java, and other clients may use separate stores. Configure their CA file/store explicitly. For example, a Python test client can use `ssl.create_default_context(cafile=...)` with the public CA PEM. Installing the Windows root is not a universal solution for every application. Never share `mitmproxy-ca.pem` or `mitmproxy-ca.p12`; those contain the CA private key.

## Capture processes without app proxy settings

```powershell
ato start --mode local --processes chrome,msedge --https decrypt
# Supported traffic from all local processes:
ato start --mode local --https decrypt
```

mitmproxy manages native Windows capture and may request elevation. A process filter is safer for initial troubleshooting. If a pinned application fails, use `--ignore-host '(^|.)example.com:443$'` or `--https passthrough`; encrypted bodies are then unavailable.

## Stop and recover connectivity

Press Ctrl+C in the gateway terminal, or run `ato stop` from the same environment/capture directory. This stops the recording, engine, and viewer. Close the separate proxy browser or relaunch it without proxy flags. If you manually enabled Windows' proxy previously, turn it off in Settings > Network & internet > Proxy. ATO does not toggle that setting.
