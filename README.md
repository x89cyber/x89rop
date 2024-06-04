# x89rop
ROP filtering tool that uses output from rp++.

### Usage
    usage: x89rop [-h] [--b B] [--c C] [--r R] [--d] [--dup] [--e E] [--i] f

    Filter saved rop gadget output from rp++

    positional arguments:
    f           path to the file from rp++ to filter

    options:
    -h, --help  show this help message and exit
    --b B       hex byte values to filter out
    --c C       comma separated list of commands to filter out
    --r R       filter by register
    --d         only include dereference commands
    --dup       remove duplicate values
    --e E       find "add esp" gadgets that equal or exceed the argument value
    --i         find interesting gadgets
