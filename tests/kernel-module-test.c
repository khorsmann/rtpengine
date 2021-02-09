#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../kernel-module/xt_RTPENGINE.h"

int main(void) {
	int fd = open("/proc/rtpengine/0/control", O_RDWR);
	assert(fd != -1);

	struct rtpengine_message rm;
	int ret;

	rm = (struct rtpengine_message) {
		.cmd = REMG_NOOP,
		.u = {
			.noop = {
				.size = sizeof(rm),
				.last_cmd = __REMG_LAST,
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	// non-forwarding
	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_TARGET,
		.u = {
			.target = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 6666,
				},
				.expected_src = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 8888,
				},
				.decrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
				.src_mismatch = MSM_IGNORE,
				.num_destinations = 0,
				.non_forwarding = 1,
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	// fowarding, incomplete
	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_TARGET,
		.u = {
			.target = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 7777,
				},
				.expected_src = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 9999,
				},
				.decrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
				.src_mismatch = MSM_IGNORE,
				.num_destinations = 1,
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	// forwarding
	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_TARGET,
		.u = {
			.target = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 9999,
				},
				.expected_src = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 5555,
				},
				.decrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
				.src_mismatch = MSM_IGNORE,
				.num_destinations = 1,
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_DESTINATION,
		.u = {
			.destination = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 9999,
				},
				.num = 0,
				.output = {
					.src_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 3333,
					},
					.dst_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 2222,
					},
					.encrypt = {
						.cipher = REC_NULL,
						.hmac = REH_NULL,
					},
				},
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	// multi forwarding, incomplete
	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_TARGET,
		.u = {
			.target = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 6543,
				},
				.expected_src = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 5555,
				},
				.decrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
				.src_mismatch = MSM_IGNORE,
				.num_destinations = 2,
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_DESTINATION,
		.u = {
			.destination = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 6543,
				},
				.num = 0,
				.output = {
					.src_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 9876,
					},
					.dst_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 7654,
					},
					.encrypt = {
						.cipher = REC_NULL,
						.hmac = REH_NULL,
					},
				},
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	// multi forwarding
	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_TARGET,
		.u = {
			.target = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 4321,
				},
				.expected_src = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 5555,
				},
				.decrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
				.src_mismatch = MSM_IGNORE,
				.num_destinations = 2,
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_DESTINATION,
		.u = {
			.destination = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 4321,
				},
				.num = 0,
				.output = {
					.src_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 3456,
					},
					.dst_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 4567,
					},
					.encrypt = {
						.cipher = REC_NULL,
						.hmac = REH_NULL,
					},
				},
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	rm = (struct rtpengine_message) {
		.cmd = REMG_ADD_DESTINATION,
		.u = {
			.destination = {
				.local = {
					.family = AF_INET,
					.u = {
						.ipv4 = htonl(0x7f000001),
					},
					.port = 4321,
				},
				.num = 1,
				.output = {
					.src_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 6543,
					},
					.dst_addr = {
						.family = AF_INET,
						.u = {
							.ipv4 = htonl(0x7f000001),
						},
						.port = 5432,
					},
					.encrypt = {
						.cipher = REC_NULL,
						.hmac = REH_NULL,
					},
				},
			},
		},
	};
	ret = write(fd, &rm, sizeof(rm));
	assert(ret == sizeof(rm));

	return 0;
}
