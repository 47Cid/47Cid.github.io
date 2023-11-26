---
layout: post
title:  "Automated Chaos: A Brief Overview of Fuzzing"
categories: [fuzzing,vulnerability-research]
tags: [fuzzing, vulnerability-research]
---

# So what is fuzzing?
Instead of giving a formal academic definition of fuzzing, I'm just going to show you a meme to give you some idea of what fuzzing is.

![This is an alt text.](/images/random.png "How do you do fellow kids?")
Fuzzing inputs are only random sometimes, but they're bs most of the time.
A more proper definition can be found [here][1]

# Fuzzing Methods:

## Whitebox fuzzing:
* Whitebox fuzzing involves fuzzing a program with complete access to its source code.
* Feedback is measured by modifying the source code during compilation of the program. But we'll get into that later 😸

## Greybox Fuzzing
* In this method, the tester has limited knowledge of the application, like function prototypes or the decompiled code.
* This approach can be really useful for fuzzing closed-source libraries with API documentation that's readily accessible.
* For example: *Microsoft DirectX*

## Blackbox Fuzzing
* When you find yourself with just the binary and no source code, this method is your best bet.
* Sometimes you might have to use emulation tools like Qemu or Unicorn to run binary files belonging to a different architecture.
* Feedback in this case is measured via binary instrumentation.

## Pitch-Blackbox Fuzzing
* Okay, so I got a little creative here and just made this term up. But by 'pitch-black' I'm referring to programs that cannot be emulated.
* For example: Programs designed to interact with specific hardware components or embedded systems firmware
* This is sometimes known as the re-hosting problem[ [5] ], and there is a lot of work yet to be done in this field [ [2], [3], [4] ].



[1]: https://owasp.org/www-community/Fuzzing
[2]: https://dl.acm.org/doi/10.1145/3423167
[3]: https://hernan.de/research/papers/firmwire-ndss22-hernandez.pdf
[4]: https://dl.acm.org/doi/10.1145/3427228.3427294
[5]: https://www.s3.eurecom.fr/docs/asiaccs22_mantovani.pdf
