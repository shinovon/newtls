# Symbian TLS 1.2 upgrade

System SSL component replacement for Symbian OS v7.0 and later.

On 9.1+ (EKA2), implementation uses dynamically linked [MBedTLS library port](https://github.com/shinovon/mbedtls-symbian), it supports TLS 1.2 or 1.2/1.3 in client mode only.

On 7.0s and 8.1a (EKA1), implementation uses statically linked [BearSSL library port](https://github.com/shinovon/bearssl-symbian), it only supports minimum basic TLS 1.2 without CA verification.

Supported software platforms:

- Symbian^3 and later (9.5+)
- S60 5th Edition (9.4)
- S60 3rd Edition and its FPs (9.1+)
- S60 2nd Edition FP3 (N70/N72/N90, 8.1a)
- S60 2nd Edition Initial Release and FP1 (6600/6260/6620/3230/7610, 7.0s)
- S80 2nd Edition (9500/9300, 7.0s)
- S90 (7700/7710, 7.0s)

NOT supported:

- S60 2nd Edition FP2 (6630/6680, 8.0a) - should work but doesn't, no idea why.
- S60 1st Edition (6.1)
- S80 1st Edition (6.0)
- Anything earlier

Unknown (theoretically should be supported, but no one tested):
- UIQ3 (9.1)
- UIQ2 (7.0s)

Installation instructions, downloads and updates are available on the [webpage](https://nnproject.cc/tls).

## Building

For EKA2 version, use Carbide.c++ v2.7/3.2, Symbian^3 SDK, RVCT 2.2.

For EKA1 version, use Carbide.c++ v2.7 and S60 2nd FP3 CW SDK with bundled gcc.

bld.inf uses macros, so it will automatically select suitable mmps for selected sdk.

[Original source](https://github.com/SymbianSource/oss.FCL.sf.os.networkingsrv/tree/BRANCH_RCL_3/networksecurity/tls)
