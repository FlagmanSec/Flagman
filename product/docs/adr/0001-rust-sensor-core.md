# 0001. Write the sensor in Rust

Status: accepted
Date: 2026-11-26

## Context

The sensor reads every packet on the network, and some of those packets may
be crafted by an attacker. It runs all day, and the same code must later run
on a router with 1 GB of memory (the OpenWrt One, for Flagman Edge). The team
knows Python well from the CS395 project.

## Decision

The sensor (`product/core`) is written in Rust: one Cargo workspace, one
crate per responsibility, no `unsafe` code in our crates.

## Consequences

- Memory safety without a garbage collector: a malformed packet cannot cause
  a buffer overflow in our parsing code, and memory use is predictable.
- One program to install, `flagmand`, with SQLite compiled in.
- Rust can build for the router's processor from a PC, which Edge will need.
- The team has to learn Rust. To help, files are small, each starts with a
  comment saying what it does, and [reading-order.md](../reading-order.md)
  gives a path through the code.
- Machine learning, which the team does in Python, is not in the sensor for
  now (see [0005](0005-rules-first-ml-later.md)).

## Alternatives considered

- **Python**: fastest for the team to write, but too slow to inspect every
  packet in pure Python, and heavy for a router.
- **C**: fast and small, but parsing hostile input in C is where many
  security bugs come from.
- **Go**: safe and simple, but its garbage collector and larger binaries
  matter on a router.
