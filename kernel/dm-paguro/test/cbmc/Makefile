# Bounded model checking of the core with CBMC (apt install cbmc).
# Memory safety everywhere, plus the functional assertions in each harness.
CHECKS := --bounds-check --pointer-check --div-by-zero-check \
	  --signed-overflow-check --undefined-shift-check --conversion-check \
	  --unwinding-assertions
INC := -I../..
.PHONY: all range claim runlist payload crc
all: range claim runlist payload crc
PAYLOAD := cbmc $(CHECKS) $(INC) -DPG_CBMC_FREE_CRC --object-bits 12 --function main payload.c
range:
	cbmc $(CHECKS) $(INC) --unwind 5 range.c ../../pg_range.c
claim:
	cbmc $(CHECKS) $(INC) --unwind 8 claim.c ../../pg_claim.c ../../pg_range.c
runlist:
	cbmc $(CHECKS) $(INC) --unwind 14 --function main runlist.c ../../pg_ntfs.c
payload:
	$(PAYLOAD) -DPATH_GPT --unwind 17
	$(PAYLOAD) -DPATH_EXT4 --unwind 17
	$(PAYLOAD) -DPATH_ISO --unwind 17
crc:
	cbmc --bounds-check --pointer-check --unwinding-assertions $(INC) --unwind 9 --function main crc.c
