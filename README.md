# comp310_A1

## Included Files
oscode.c
lists.c
lists.h
Makefile

## Usage
To build, run ```make```
This produces an executable called oscode
Run with ```./oscode```

## Comments
1. I use a global shared variable to handle background process error detection.
This method has not been thoroughly tested and it is possible that a race condition on
the variable may result if multiple background processes fail at once. Please do not try
running this program with multiple background processes that you expect to fail at once.
