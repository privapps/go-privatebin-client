# PrivateBin CLI

A CLI for PrivateBin allowing easy pasting from the Terminal.

## Installation

Download latest binaries from https://github.com/privapps/go-privatebin-client/tree/latest-binaries

## Advantage
This go client is much faster than the python client e.g. (0.5 seconds vs. 2+ seconds)

## Limitation

* zlib compress is not supported see https://github.com/golang/go/issues/28594 
* Only support encryption pipe from command line

## Usage
```
  -dry
        dry run. not send to the host, output json and hash
  -expire string
        expire time, values[ 1day, 1week, 1month, never ] (default "1day")
  -host string
        private bin host url (default "https://privatebin.net")
  -key string
        hash key to encrypt
```
Currently, `privatebin` only support piping inputs on the Command Line.

```shell script
# Using Echo
echo test | privatebin

# Using Tail
tail -n 20 <FILE> | privatebin -expire 10min -host https://bin.snopyta.org

# Using Cat
cat <FILE> | privatebin -key Hbod5EmjRUR8WMC6hTPSPtEj6wzYN4v4zdksM9Md2psM -dry
```
