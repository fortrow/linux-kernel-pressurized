# SPDX-License-Identifier: GPL-2.0
CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2
OUT_DIR := $(CURDIR)/../dev/shared

BINS := \
	$(OUT_DIR)/pressure-authd \
	$(OUT_DIR)/pressure-authctl \
	$(OUT_DIR)/press \
	$(OUT_DIR)/sure \
	$(OUT_DIR)/sfw \
	$(OUT_DIR)/sfw-curl \
	$(OUT_DIR)/sfw-dhcp \
	$(OUT_DIR)/sfw-resolve \
	$(OUT_DIR)/sfw-connect \
	$(OUT_DIR)/pam_pressure.so \
	$(OUT_DIR)/libpressureshim.so \
	$(OUT_DIR)/pressure_e2e_test

.PHONY: all clean copy-policies

all: $(OUT_DIR) $(BINS) copy-policies

$(OUT_DIR):
	mkdir -p "$(OUT_DIR)" "$(OUT_DIR)/policies"

copy-policies:
	mkdir -p "$(OUT_DIR)/policies"
	cp -f policies/*.pr "$(OUT_DIR)/policies/"
	cp -f tests/run_pressure_tests.sh "$(OUT_DIR)/run_pressure_tests.sh"
	chmod +x "$(OUT_DIR)/run_pressure_tests.sh"

$(OUT_DIR)/pressure-authd: authd/pressure_authd.c authd/authd_proto.h
	$(CC) $(CFLAGS) $< -lcrypto -o $@

$(OUT_DIR)/pressure-authctl: authd/pressure_authctl.c authd/authd_proto.h
	$(CC) $(CFLAGS) $< -o $@

$(OUT_DIR)/pam_pressure.so: pam/pam_pressure.c authd/authd_proto.h
	$(CC) $(CFLAGS) -fPIC -shared $< -lpam -o $@

$(OUT_DIR)/press: press/press.c authd/authd_proto.h ../include/uapi/linux/sfw.h
	$(CC) $(CFLAGS) $< -lpam -o $@

$(OUT_DIR)/sure: sure/sure.c sure/policy_parser.c sure/policy_parser.h ../include/uapi/linux/sfw.h
	$(CC) $(CFLAGS) sure/sure.c sure/policy_parser.c -o $@

$(OUT_DIR)/sfw: sfw/sfw_cli.c
	$(CC) $(CFLAGS) $< -o $@

$(OUT_DIR)/sfw-curl: sfw/sfw_curl.c sfw/sfw_dns.c sfw/sfw_dns.h $(OUT_DIR)/libpressuresock.o
	$(CC) $(CFLAGS) $(filter-out %.h,$^) -lresolv -o $@

$(OUT_DIR)/sfw-dhcp: sfw/sfw_dhcp.c ../include/uapi/linux/sfw.h $(OUT_DIR)/libpressuresock.o
	$(CC) $(CFLAGS) $(filter-out %.h,$^) -o $@

$(OUT_DIR)/sfw-resolve: sfw/sfw_resolve.c sfw/sfw_dns.c sfw/sfw_dns.h $(OUT_DIR)/libpressuresock.o
	$(CC) $(CFLAGS) $(filter-out %.h,$^) -lresolv -o $@

$(OUT_DIR)/sfw-connect: sfw/sfw_connect.c sfw/sfw_dns.c sfw/sfw_dns.h $(OUT_DIR)/libpressuresock.o
	$(CC) $(CFLAGS) $(filter-out %.h,$^) -lresolv -o $@

$(OUT_DIR)/libpressuresock.o: libpressure/libpressuresock.c libpressure/libpressuresock.h
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(OUT_DIR)/libpressureshim.so: libpressure/libpressureshim.c $(OUT_DIR)/libpressuresock.o
	$(CC) $(CFLAGS) -fPIC -shared $^ -ldl -lpthread -o $@

$(OUT_DIR)/pressure_e2e_test: tests/pressure_e2e_test.c $(OUT_DIR)/libpressuresock.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(BINS) $(OUT_DIR)/libpressuresock.o
