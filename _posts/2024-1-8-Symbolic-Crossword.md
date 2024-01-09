---
layout: post
title:  "Solving Crosswords with Symbolic Analysis"
categories: [symbolic-analysis]
tags: [symbolic-analysis, vulnerability-research, misc, ]
---

## What is symbolic execution?
You can think of symbolic exeuction as a process of creating a mapping between variables (mathematical variables, NOT programming variables) and the control flow graph. 
> What part of the program is executed when supplied with a given value and vice-versa.

![Control Flow Graph](/images/cfg.svg)

Aside from being able to solve your Algebra homework, symbolic execution has numerous important use cases.
* Test Case Generation 
* Bug Discovery and Vulnerabily Research
* Satisfiability modulo theories (SMTs)
* Type Inference

## Crosswords
Another neat way to apply symbolic exectution, is to make a crossword solving program.

Here's a snippet from the crossword puzzle program: 

```c
for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            // Get user value if the field is blank
            if(puzzle[i][j] == '.'){
                printf("Enter value for puzzle[%d][%d]: ", i, j);
                char a; 
                scanf(" %c", &puzzle[i][j]);
                printPuzzle(puzzle);

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
> The rest of the (tribble) code can be found here: https://github.com/47Cid/Symbolic-Crossword/tree/main 

The program gets a value from the user, updates the crossword grid, and then checks if it was the intended solution.  
So what we need to find out here is what value will go into the "correct" branch.  
This problem is well-suited for symbolic execution.

I am going to be using the [KLEE](https://klee.github.io/docs/) symbolic engine.