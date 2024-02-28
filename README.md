# CT437 A2 - Using and Benchmarking Blockciphers with OpenSSL

## Overview

In this assignment, OpenSSL is used to encrypt and decrypt data using different blockciphers. The CPU time of each algorithm is measured and compared in the accompanying report.

The source code, binaries and results of each problem are provided in this repository.

## Problem 1: Blockcipher Benchmarking

In this section, the following encryption settings are first measured (CPU time) and then contrast:

- AES, ARIA and Camellia Algorithm
- 128 and 256 bit key length
- ECB, CBC and GCM mode
- 10 MB and 100 MB of data
- encoding and decoding

## Problem 2: Implementing and Benchmarking Triple-DES

In this section, Triple-DES is implemented using OpenSSL's DES API with support for both CBC and ECB mode. Each mode is benchmarked using 100 MB of data and compared with the 100 MB results in Problem 1.

## Results:

