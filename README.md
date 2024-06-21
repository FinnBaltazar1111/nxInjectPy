# nxInjectPy
Useful tool to inject a Nintendo Switch payload in Python, without specifying the payload's location.

# Usage
**Building is not required**. Just clone this repository and run `main.py`, or to continuously run (useful for dongles, which can auto-inject preset payloads), use `repeat.sh`. Default payload is [hekate v6.2.0](https://github.com/CTCaer/hekate/releases/tag/v6.2.0). If you prefer a different payload, replace `payload.bin` with your payload, and, of course, **make sure it's named `payload.bin`**.

# Credits
- [CTCaer](https://github.com/CTCaer/), for providing [hekate](https://github.com/CTCaer/hekate/)
- [Nintendo](https://github.com/Nintendo/), for programming and releasing awesome video games and consoles, for not actively patching glitches in [Super Mario Odyssey](https://www.nintendo.com/us/store/products/super-mario-odyssey-switch/) (one of my *favorite* video games), and for not actively patching the [Nintendo Switch hacks](https://nh-server.github.io/switch-guide/] that our community works *so* hard on.
- [Python](https://github.com/python/), for providing what is objectively one of the *best* programming languages out there (sorry, C++).
- [mcuee](https://github.com/mcuee/), for providing [libusbK](https://github.com/mcuee/libusbk/).
