# Python version of `traceroute`

Implemented as an educational task for the Computer Networks course.

Inspired by [rust implementation](https://petermalmgren.com/rust-tracepath/).

## Usage

Seems like there is no way to use raw socket in python3 without root, neither to read ICMP errors from UDP socket (`IP_RECVERR` linux flag). Therefore, run the program as:

```bash
sudo python3 traceroute.py 1.1.1.1
```

Type `python3 traceroute.py -h` for help.
