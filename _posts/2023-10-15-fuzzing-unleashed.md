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

#### But hold on, there's more! 
#### Let's begin with a more targeted approach to explore the world of fuzzing.
#### Let's begin with...

# Fuzzing Methods

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
* Okay, so I got a little creative here and just made this term up. But by 'pitch-black' I mean programs that cannot be emulated.
* For example: Programs designed to interact with specific hardware components.
* This is sometimes known as the re-hosting problem[ [5] ], and there is a lot of work yet to be done in this field [ [2], [3], [4] ].

# But what really is feedback?
During feedback-driven fuzzing the fuzzer leverages the feedback obtained from the target process and adapts its input generation based said feedback.
Feedback is usually measured using various metrics such as:
1) Code Coverage: The extent to which the source code of a program has been executed during the testing process
2) Edge Coverage: Measurement of the transitions between basic blocks in the control flow graph of the program.
3) Memory Usage: Tracking allocation and deallocation of memory during program execution.

The terms "feedback-driven" and "coverage-guided" are frequently used interchangeably, but they are not the same for reasons explained above.
## Source Code Instrumentation:
Fuzzers can instrument the source code to collect coverage information by directly modifying it to add additional code during compilation.
AFL enables source code instrumentation by integrating with other compilers. 
```bash
afl-gcc fuzz.c -o fuzz
```
AFL can also use the LLVM compiler to insert instrumentation code using LLVM passes
```bash
afl-clang-lto fuzz.c -o fuzz
```

## Binary Instrumentation:  
Binary instrumentation, as the name suggests, involves modifying the compiled binary code of a program to insert additional instructions.

For instance, you can use dynamic instrumentation toolkits like [Frida](https://frida.re/) to inject JavaScript or native code into running processes or intercept and modify function calls.

> **Note:** It might be possible to whip up a coverage guided fuzzer using Frida, but I'm not sure how well it would perform.


[1]: https://owasp.org/www-community/Fuzzing
[2]: https://dl.acm.org/doi/10.1145/3423167
[3]: https://hernan.de/research/papers/firmwire-ndss22-hernandez.pdf
[4]: https://dl.acm.org/doi/10.1145/3427228.3427294
[5]: https://www.s3.eurecom.fr/docs/asiaccs22_mantovani.pdf
