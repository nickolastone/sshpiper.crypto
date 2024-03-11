module asm

go 1.22

toolchain go1.22.1

require (
	github.com/mmcloughlin/avo v0.4.0
	golang.org/x/crypto v0.0.0
)

replace golang.org/x/crypto v0.0.0 => ../../../..
