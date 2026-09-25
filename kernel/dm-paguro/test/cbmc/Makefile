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
	# One path per run, per-loop bounds: each is seconds and < 1 GB (a blanket
	# --unwind 17 made the GPT path exhaust 30 GB). The GPT runs take
	# payload_ext4 as its contract (PG_CBMC_STUB_EXT4); the EXT4 run proves it.
	$(PAYLOAD) -DPATH_GPT -DPG_CBMC_STUB_EXT4 -DLBS=512 --unwind 9 \
	    --unwindset payload_gpt.0:17,payload_gpt.1:17,payload_gpt.2:6,eq.0:17
	$(PAYLOAD) -DPATH_GPT -DPG_CBMC_STUB_EXT4 -DLBS=4096 --unwind 9 \
	    --unwindset payload_gpt.0:17,payload_gpt.1:17,payload_gpt.2:6,eq.0:17
	$(PAYLOAD) -DPATH_EXT4 --unwind 17
	$(PAYLOAD) -DPATH_ISO --unwind 9
crc:
	cbmc --bounds-check --pointer-check --unwinding-assertions $(INC) --unwind 9 --function main crc.c
