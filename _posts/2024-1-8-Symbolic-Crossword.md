---
layout: post
title:  "Solving Crosswords with Symbolic Analysis"
categories: [symbolic-analysis]
tags: [symbolic-analysis, vulnerability-research, misc, ]
---

## What is symbolic execution?
You can think of symbolic execution as a process of creating a mapping between variables (mathematical variables, NOT programming variables) and the control flow graph. 
> What part of the program is executed when supplied with a given value and vice-versa?

![Control Flow Graph](/images/cfg.svg)

Aside from being able to solve your Algebra homework, symbolic execution has numerous important use cases.
* Test Case Generation 
* Bug Discovery and Vulnerability Research
* Satisfiability modulo theories (SMTs)
* Type Inference

## Crosswords
Another neat way to apply symbolic execution is to make a crossword-solving program.

Here's a snippet from the crossword puzzle program: 

```c
for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            // Get user value if the field is blank
            if(puzzle[i][j] == '.'){
                printf("Enter value for puzzle[%d][%d]: ", i, j);
                scanf(" %c", &puzzle[i][j]);
                printPuzzle(puzzle);

            // Check if the entered value is correct
                if (puzzle[i][j] == solution[index]) {
                    printf("Correct!\n");
                } else {
                    printf("Incorrect. Expected: %c\n", solution[i]);
                }

                return;
            }
        }
    }
```
> The rest of the (terrible) code can be found here: https://github.com/47Cid/Symbolic-Crossword/tree/main 

The program gets a value from the user, updates the crossword grid, and then checks if it is the intended solution.  
So what we need to find out here is what value will go into the "correct" path.  
This problem is well-suited for symbolic execution.

I am going to be using the [KLEE](https://klee.github.io/docs/) symbolic execution engine for this.

As opposed to using fixed, concrete values, symbolic values are used during symbolic execution, i.e. a variable value.
How these values are varied depends on the symbolic execution engine.

So, instead of getting a concrete value from the user, we need a symbolic value.  
This is how you can use the KLEE API to make a symbolic value:
```c
//scanf(" %c", &puzzle[i][j]);
klee_make_symbolic(&a, sizeof(a), "a");
puzzle[i][j] = a;
```

Now that we have a symbolic value, we can execute the program symbolically.
> Make sure to add '#include<klee/klee.h>'

The symbolic execution engine will explore all the paths of our program.
However, we don't care about all the paths. We just want to find the values that make the __puzzle[i][j]__ == __solution[index]__ condition true.  
Basically, we need KLEE to inform us when our desired condition is met by throwing an error. This can be done using the "klee_assert()" function.
```c
if (puzzle[i][j] == solution[index]) {
    printf("Correct!\n");
    klee_assert(0);
} 
```

Now we can compile our code into LLVM bitcode and run KLEE.

```shell
clang -I ./klee_build/include/ -emit-llvm -c crossword.c
klee --emit-all-errors crossword.bc
```
> **Note:** KLEE will only give you the first error condition by default. So, we need to use the --emit-all-erros flag.

## Solution
Sample crossword puzzle:
```c
char puzzle[SIZE][SIZE] = {
        {'C', 'A', '.'},
        {'A', '.', 'E'},
        {'N', '.', '.'},
};
```
The solution to this trivial crossword puzzle is: 
```c
char puzzle[SIZE][SIZE] = {
        {'C', 'A', 'N'},
        {'A', 'G', 'E'},
        {'N', 'O', 'W'},
};
```

As expected, KLEE was able to calculate the solutions(i.e. N, G, O, and W respectively).

![](/images/1.png)

![](/images/2.png)

![](/images/3.png)

![](/images/4.png)

## References
https://feliam.wordpress.com/2010/10/07/the-symbolic-maze/
https://klee.github.io/docs/