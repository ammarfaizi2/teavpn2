// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <teavpn2/common.h>

void show_version(void)
{
	puts("----------------------------------------------------------");
	puts("TeaVPN2 " TEAVPN2_VERSION "\n");
	puts("Copyright (C) 2021 Ammar Faizi\n"
	     "This is free software; see the source for copying conditions.  There is NO\n"
	     "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
	puts("GitHub repo: https://github.com/TeaInside/teavpn2\n");
}

static void show_general_usage(const char *app)
{
	printf("Usage: %s [client|server] [options]\n\n", app);
	printf("  For help, see:\n");
	printf("    %s client --help\n", app);
	printf("    %s server --help\n", app);
	printf("\n");
	show_version();
}

static int run_teavpn2(int argc, char *argv[])
{
	if (!strcmp("server", argv[1]))
		return run_server(argc, argv);

	if (!strcmp("client", argv[1]))
		return run_client(argc, argv);

	if (!strcmp("--version", argv[1]) || !strcmp("-V", argv[1])) {
		show_version();
		return 0;
	}

	if (!strcmp("--help", argv[1]) || !strcmp("-H", argv[1])) {
		show_general_usage(argv[0]);
		return 0;
	}

	printf("Invalid command: %s\n", argv[1]);
	show_general_usage(argv[0]);
	return 1;
}

static void fix_stdio_buffer(void)
{
	/*
	 * Explicitly set the buffer to _IOLBF (line buffered).
	 * This is important to make sure the buffer is always
	 * line buffered, especially when we redirect the output
	 * input a file, like:
	 *   ./teavpn2 server -c config.ini >> server.log 2>&1;
	 *
	 * Without setting it up to `_IOLBF` here, the buffer
	 * will be full buffered when the above redirect is done.
	 */
	if (setvbuf(stdout, NULL, _IOLBF, 2048))
		printf("Cannot set stdout buffer: %s\n", strerror(errno));
	if (setvbuf(stderr, NULL, _IOLBF, 2048))
		printf("Cannot set stderr buffer: %s\n", strerror(errno));
}

int main(int argc, char *argv[])
{

	fix_stdio_buffer();
	if (argc == 1) {
		show_general_usage(argv[0]);
		return 0;
	}

#ifdef CONFIG_HPC_EMERGENCY
	if (emerg_init_handler(EMERG_INIT_BUG | EMERG_INIT_WARN)) {
		int ret = errno;
		printf("Cannot set emerg handler: %s\n", strerror(ret));
		return -ret;
	}
#endif
	return run_teavpn2(argc, argv);
}
