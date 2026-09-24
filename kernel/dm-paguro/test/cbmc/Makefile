# Bounded model checking of the core with CBMC (apt install cbmc).
# Memory safety everywhere, plus the functional assertions in each harness.
CHECKS := --bounds-check --pointer-check --div-by-zero-check \
	  --signed-overflow-check --undefined-shift-check --conversion-check \
	  --unwinding-assertions
INC := -I../..
.PHONY: all range claim runlist
all: range claim runlist
range:
	cbmc $(CHECKS) $(INC) --unwind 5 range.c ../../pg_range.c
claim:
	cbmc $(CHECKS) $(INC) --unwind 8 claim.c ../../pg_claim.c ../../pg_range.c
runlist:
	cbmc $(CHECKS) $(INC) --unwind 14 --function main runlist.c ../../pg_ntfs.c
