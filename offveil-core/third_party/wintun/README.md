# Wintun (signed DLL)

Official signed `wintun.dll` from [wintun.net](https://www.wintun.net/).

| Item | Value |
|------|--------|
| Version | 0.14.1 |
| ZIP SHA256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| Arch here | amd64 |

**Do not** redistribute renamed/rebuilt drivers. Side-by-side with `offveil-core.exe` only.

```powershell
.\scripts\fetch-wintun.ps1
# then copy next to the binary:
Copy-Item third_party\wintun\wintun.dll .\wintun.dll
```
