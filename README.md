# Semi-Laconic Private Set Intersection Based on Pairings

This project implements a Semi-Laconic Private Set Intersection (PSI) protocol based on pairings.

## Required Libraries
Before building the project, ensure the following libraries are installed:

1. **OpenSSL**
2. **GMP**
3. **Relic**

## Build the Project

```bash
mkdir build
cd build
cmake ..
make
```

## Running the Code
- `-p`: Port number
- `-t`: Number of threads
- `-n`: Sender's dataset log size
- `-m`: Receiver's dataset log size

## Example
``` bash
./bin/Semi_Honest_sender -p 1234 -n 8 -m 8 -t 2
./bin/Semi_Honest_receiver -p 1234 -n 8 -m 8 -t 2
```
