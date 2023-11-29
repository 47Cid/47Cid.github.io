---
layout: post
title:  "Automated Chaos: A Brief Overview of Fuzzing"
categories: [fuzzing,vulnerability-research]
tags: [fuzzing, vulnerability-research]
---

# What is fuzzing, really?
![This is an alt text.](/images/random.png "Much random")
> **Note:** Fuzzing inputs are only random sometimes, but they're bs most of the time.


#### Let's first try to understand fuzzing by looking at some of the...

# Fuzzing Methods

## Whitebox fuzzing:
* Whitebox fuzzing involves fuzzing a program with complete access to its source code.
* Feedback is measured by modifying the source code during the compilation of the program (But we'll get into that later)

Fuzzing tools suited for whitebox testing: [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus), [libFuzzer](https://llvm.org/docs/LibFuzzer.html), [Honggfuzz](https://github.com/google/honggfuzz), [python-afl](https://github.com/jwilk/python-afl)

## Greybox Fuzzing
* In this method, the tester has limited knowledge of the application, like function prototypes or the decompiled code.
* This approach can be really useful for fuzzing closed-source libraries with API documentation that's readily accessible.
* For example: *Microsoft Windows API*

Fuzzing tools suited for grebox testing: [syzkaller](https://github.com/google/syzkaller/tree/master), [Hopper](https://github.com/FuzzAnything/Hopper), [aflnet](https://github.com/aflnet/aflnet), [aflgo](https://github.com/aflgo/aflgo), [boofuzz](https://github.com/jtpereyda/boofuzz), [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus)

## Blackbox Fuzzing
* When you find yourself with just the binary and no source code, this method is your best bet.
* Sometimes you might have to use emulation tools like Qemu or Unicorn to run binary files belonging to a different architecture.
* Feedback in this case is measured via binary instrumentation.

Fuzzing tools suited for blackbox testing: [radamsa](https://gitlab.com/akihe/radamsa), [winafl](https://github.com/googleprojectzero/winafl), [Peach Fuzzer](https://peachtech.gitlab.io/peach-fuzzer-community/), [AFLPlusPlus](https://github.com/AFLplusplus/AFLplusplus)

## Pitch-Blackbox Fuzzing
* Okay, so I got a little creative here and just made this term up. But by 'pitch-black' I mean programs that cannot be emulated.  This distinction becomes really important when it comes to dynamic analysis like fuzzing.
* For example: Programs designed to interact with specific hardware components.
* This is known as the re-hosting problem[ [5] ]. This is a really big problem and there's very limited work done in this field [ [2], [3], [4] ].

Fuzzing tools suited for pitch-blackbox testing: 🌵🌀

> **Note:** Okay, maybe [Firmwire](https://github.com/FirmWire/FirmWire) is an exception, but I'm not familiar with any other fuzzing tools like this. Hit me up on [Discord](https://discord.com/users/244064067541663744) if you know something I don't.

## But what is feedback?
We need to somehow measure the efficacy of a fuzzing test.
We need to get some kind of 'feedback' from the process while it's being fuzzed.

The fuzzer could then leverage the feedback obtained from the target process and adapt its input generation.

Feedback is usually measured using various metrics such as:
1) Code Coverage: This is the most important form of feedback. It measures the extent to which the source code of a program has been executed during the testing process
2) Edge Coverage: Even [100%](https://roelofjanelsinga.com/articles/100-test-coverage-why-or-why-not/) code coverage does not guarantee effective testing. As such, measurement of the transitions between basic blocks in the control flow graph of the program can also provide useful insight during fuzzing.
3) Memory Usage: It can also be useful to keep track of how the target application allocates and deallocates memory during the execution of test cases. Generating inputs that lead to frequent memory allocations is an [effective](https://securitylab.github.com/research/fuzzing-software-2/) way of uncovering new bugs.
4) Input Validation: It might be helpful for the fuzzer to know whether the input being supplied to the target process is valid.

> **Note:** The terms "feedback-driven" and "coverage-guided" are frequently used interchangeably, but they are not necessarily the same. Feedback-driven fuzzing is a broader term that encompasses coverage-guided fuzzing.

### Coverage Tools
#### afl-plot
Useful for generating graphical representations of AFL's performance and coverage data.

#### afl-cov
Provides code coverage information collected during the fuzzing campaign

### Code Coverage visualizers

#### VSCode
* [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters)
#### Ghidra 
* [Cartographer](https://github.com/nccgroup/Cartographer)
* [Dragondance](https://github.com/0ffffffffh/dragondance)

## Instrumentation
Instrumentation is the process of injecting additional code into a program to collect data about its runtime or to modify the program's behavior.

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

> **Note:** It might be possible to whip up a pretty interesting coverage-guided fuzzer using Frida, but I'm not sure how well it would perform. To my knowledge, I don't think anyone has done this. 


## Mutations
Mutation-based fuzzing is a technique where new test inputs are generated by tweaking existing inputs.

In the case of feedback-driven fuzzing, the feedback information is used to guide further mutations.
Inputs that lead to new or uncovered code paths are considered interesting and may be prioritized for further mutation.

### Mutation techniques:

### Random
In AFL terminology, one of the most common mutation strategies is the "havoc" technique. This involves aggressive and chaotic mutations like random bit/byte flipping.

![Random](https://imgs.xkcd.com/comics/im_so_random_2x.png )
Source: https://xkcd.com/

### Lexical
For higher code coverage, it's beneficial for the input data to contain certain "interesting" characters or tokens.

[State of the art fuzzers](https://lcamtuf.blogspot.com/2014/11/afl-fuzz-nobody-expects-cdata-sections.html), will analyze comparison operations to extract such interesting constants that enable the fuzzer to generate input data that can explore more branches. 

Examples:
>if (strcmp(header.magic_password, "h4ck3d by p1gZ")) goto terminate_now;

>if (header.magic_value == 0x12345678) goto terminate_now;

This method by itself can be extremely powerful, such as mutating a string into valid [JPEG images](https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html). 

You could also further enhance this by making use of [AFL Dictionaries](https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/README.md) by generating a set of valid inputs to guide the mutation process. 

Lexical mutations involve modifying the input data while taking into account these specific values, like deleting, or substituting characters or tokens.

### Syntactic
This is useful for fuzzing programs that require highly structured inputs such as interpreters and compilers[ [6] ]. Additionally, you can think of this as feeding the target program input data that can find crashes "deeper" in the program.

Grammar-aware fuzzing is usually done by providing the fuzzer a grammar file. [ [7], [8], [9] ]

> **Note:** The grammar file doesn't have to be comprehensive for fuzzing purposes. But exactly how much "structure" one should provide to find the most bugs is an interesting question. Again, if you know something about this....([Discord](https://discord.com/users/244064067541663744))

### Semantic
Semantic mutations require an understanding of the underlying semantics program's API, such as the s function signatures and type definitions [ [10] ].

> **Note:** AFL doesn't really fall into any one category because it allows you to write your own [custom mutators](https://aflplus.plus/features/).

## Input Seed Generation:
The initial set of seed inputs in the corpus serves as a starting point for the fuzzer. These seeds are typically valid inputs that help the fuzzer understand the structure and expected format of input data.


Generate More Crashes (Santizers)
ASAN works by mapping the program's memory to a shadow map. This takes up more space and hence the -m none flag is needed

## Some common pitfalls:

### IO 
Too much IO is bad!
* https://barro.github.io/2018/06/afl-fuzz-on-different-file-systems/
* https://www.cipherdyne.org/blog/2014/12/ram-disks-and-saving-your-ssd-from-afl-fuzzing.html

TLDR: tmpfs based file system is best. It's also better than ramfs because it does not grow dynamically

I also added --memory tag

```bash
docker pull aflplusplus/aflplusplus

docker run -ti -v ~/src-dir:/src --memory=1024m \
--mount type=tmpfs,destination=/ramdisk -e \
AFL_TMPDIR=/ramdisk aflplusplus/aflplusplus
```

### Networking

### Syscalls



[1]: https://owasp.org/www-community/Fuzzing
[2]: https://dl.acm.org/doi/10.1145/3423167
[3]: https://hernan.de/research/papers/firmwire-ndss22-hernandez.pdf
[4]: https://dl.acm.org/doi/10.1145/3427228.3427294
[5]: https://www.s3.eurecom.fr/docs/asiaccs22_mantovani.pdf
[6]: https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-3_Aschermann_paper.pdf
[7]: https://github.com/nautilus-fuzz/nautilus/tree/master
[8]: https://github.com/AFLplusplus/Grammar-Mutator/tree/stable
[9]: https://github.com/vrthra/F1
[10]: https://arxiv.org/pdf/2309.03496.pdf

## Some additional refrences