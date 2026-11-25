// SPDX-License-Identifier: GPL-2.0
/* Resolve HTTPS targets and run curl through the Pressure SFW socket shim. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sfw_dns.h"

static int run_curl(const char *url, const char *mapping)
{
	char buffer[4096];
	int output[2], status = 0, result = 0;
	ssize_t count;
	pid_t child;

	if (pipe(output) < 0)
		return 1;
	child = fork();
	if (child < 0) {
		close(output[0]);
		close(output[1]);
		return 1;
	}
	if (!child) {
		int input = open("/dev/null", O_RDONLY);

		close(output[0]);
		if (input < 0 || dup2(input, STDIN_FILENO) < 0 ||
		    dup2(output[1], STDOUT_FILENO) < 0 ||
		    dup2(output[1], STDERR_FILENO) < 0)
			_exit(1);
		close(input);
		close(output[1]);
		if (setenv("LD_PRELOAD", "/usr/lib/libpressureshim.so", 1) < 0)
			_exit(1);
		execl("/usr/libexec/pressure-curl", "curl", "-q", "--ipv4",
		      "--silent", "--show-error", "--globoff", "--noproxy", "*",
		      "--proto", "=https", "--connect-timeout", "10",
		      "--max-time", "120", "--fail", "--cacert",
		      "/etc/ssl/certs/ca-certificates.crt", "--resolve",
		      mapping, "--url", url, (char *)NULL);
		perror("sfw-curl");
		_exit(1);
	}
	close(output[1]);
	/* Keep control characters from remote content out of the desktop PTY. */
	while ((count = read(output[0], buffer, sizeof(buffer))) > 0) {
		for (ssize_t i = 0; i < count; i++) {
			unsigned char byte = buffer[i];

			if (byte >= 0x20 && byte <= 0x7e)
				fputc(byte, stdout);
			else if (byte == '\n' || byte == '\t')
				fputc(byte, stdout);
			else
				fprintf(stdout, "\\x%02x", byte);
		}
		if (fflush(stdout) == EOF) {
			result = 1;
			break;
		}
	}
	close(output[0]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    count < 0 || result)
		return 1;
	return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
	char host[254], text[INET_ADDRSTRLEN], mapping[300];
	struct in_addr address;
	const char *authority;
	size_t length;
	int pipefd[2], status;
	pid_t resolver;

	if (argc != 2 || strncmp(argv[1], "https://", 8))
		goto usage;
	authority = argv[1] + 8;
	length = strcspn(authority, "/?#");
	if (!length || length >= sizeof(host) ||
	    strspn(authority, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-") != length)
		goto usage;
	memcpy(host, authority, length);
	host[length] = '\0';
	if (inet_pton(AF_INET, host, &address) != 1) {
		if (pipe(pipefd) < 0)
			goto dns_error;
		resolver = fork();
		if (resolver < 0)
			goto dns_error;
		if (!resolver) {
			close(pipefd[0]);
			alarm(10);
			if (sfw_resolve_ipv4(host, &address) < 0 ||
			    write(pipefd[1], &address, sizeof(address)) != sizeof(address))
				_exit(1);
			_exit(0);
		}
		close(pipefd[1]);
		/* DNS response provenance stays in the disposable resolver process. */
		ssize_t size = read(pipefd[0], &address, sizeof(address));
		close(pipefd[0]);
		if (waitpid(resolver, &status, 0) != resolver || size != sizeof(address) ||
		    !WIFEXITED(status) || WEXITSTATUS(status))
			goto dns_error;
	}
	if (!inet_ntop(AF_INET, &address, text, sizeof(text)))
		goto dns_error;
	snprintf(mapping, sizeof(mapping), "%s:443:%s", host, text);
	return run_curl(argv[1], mapping);

dns_error:
	fputs("sfw-curl: SFW IPv4 DNS resolution failed\n", stderr);
	return 1;
usage:
	fputs("Usage: sfw-curl https://HOST/PATH\n", stderr);
	return 2;
}
