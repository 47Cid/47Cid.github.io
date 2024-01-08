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
