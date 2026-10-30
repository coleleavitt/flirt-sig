# flirt-sig

Reader for IDA FLIRT `.sig` signature files, format versions 5 to 11.

```
flirt-sig <file.sig> [--dump N|all]
```

prints the header, the module count and the first N modules (default 5).

The parser reads every one of the 212 signature files shipped with IDA 9.5
(versions 5, 6, 7, 9, 10 and 11, about 4.7 million modules) to the last byte.
