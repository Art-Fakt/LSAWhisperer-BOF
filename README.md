# LSAWhisperer-BOF

Port of [LSA Whisperer](https://github.com/EvanMcBroom/lsa-whisperer) by Evan McBroom / SpecterOps to the **Adaptix C2** BOF framework.

Interacts with Windows LSA Authentication Packages (MSV1_0, Kerberos, CloudAP) via `LsaCallAuthenticationPackage` to extract credentials, tickets, and SSO cookies.

## Commands

### MSV1_0 Module

| Command | Description | Requires Elevation |
|---------|------------|-------------------|
| `lsa-credkey` | Recover DPAPI credential key for a logon session | Yes |
| `lsa-strongcredkey` | Recover strong credential key (Win10+) | Yes |
| `lsa-ntlmv1` | Generate NTLMv1 challenge response (for hash cracking) | Yes |

### Kerberos Module

| Command | Description | Requires Elevation |
|---------|------------|-------------------|
| `lsa-klist` | List cached Kerberos tickets | No (own) / Yes (others) |
| `lsa-dump` | Dump full Kerberos ticket (kirbi format) | No (own) / Yes (others) |
| `lsa-purge` | Purge cached Kerberos tickets | No (own) / Yes (others) |

### CloudAP Module

| Command | Description | Requires Elevation |
|---------|------------|-------------------|
| `lsa-ssocookie` | Get Azure AD SSO cookie (PRT cookie) | No (own) / Yes (others) |
| `lsa-devicessocookie` | Get Device SSO cookie | No (own) / Yes (others) |
| `lsa-enterprisesso` | Get Enterprise SSO cookie | No (own) / Yes (others) |
| `lsa-cloudinfo` | Get CloudAP info (provider, TGT, DPAPI status) | No (own) / Yes (others) |

## Options

All commands accept an optional `-l` flag to specify a target LUID:

```
lsa-klist -l 0x3e7
lsa-credkey -l 0x1a2b3
```

Without `-l`, the command targets the current session. Targeting other sessions requires elevation (SYSTEM).

The `lsa-ntlmv1` command also accepts a `-c` flag for the server challenge:

```
lsa-ntlmv1 -c 1122334455667788
```

The default challenge `1122334455667788` is used if not specified (compatible with crack.sh free cracking).

## Build

```bash
make all      # Build all modules (x64 + x86)
make clean    # Remove compiled objects
```

Requires MinGW cross-compilers:
- `x86_64-w64-mingw32-gcc`
- `i686-w64-mingw32-gcc`

### Output

```
_bin/msv1_0_bof.x64.o
_bin/msv1_0_bof.x86.o
_bin/kerberos_bof.x64.o
_bin/kerberos_bof.x86.o
_bin/cloudap_bof.x64.o
_bin/cloudap_bof.x86.o
```

## Credits

- Original tool: [LSA Whisperer](https://github.com/EvanMcBroom/lsa-whisperer) by Evan McBroom / SpecterOps (MIT License)
- Adaptix C2 port: Adapted for the Adaptix BOF framework
