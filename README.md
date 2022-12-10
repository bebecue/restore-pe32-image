Restore the original PE32 image from process memory

## Build

```
$ cl memdump.c

Microsoft (R) C/C++ Optimizing Compiler Version 19.32.31329 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

memdump.c
Microsoft (R) Incremental Linker Version 14.32.31329.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:memdump.exe
memdump.obj
```

```
$ cl restore.c

Microsoft (R) C/C++ Optimizing Compiler Version 19.32.31329 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

restore.c
Microsoft (R) Incremental Linker Version 14.32.31329.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:restore.exe
restore.obj
```

## Usage

1. load executable with debugger, break at entry point

1. dump the loaded image from process memory with `memdump.exe <PID> target_dump.bin`

1. restore it to the original image with `restore.exe target_dump.bin target_dump.exe`

`target_dump.exe` should be identical to original executable

## TODO

- [ ] restore PE32+ (x86_64) image
