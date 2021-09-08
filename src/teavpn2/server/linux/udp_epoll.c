// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/server/common.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/udp.h>


static int create_epoll_fd(void)
{
	int ret = 0;
	int epoll_fd;

	epoll_fd = epoll_create(255);
	if (unlikely(epoll_fd < 0)) {
		ret = errno;
		pr_err("epoll_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	return epoll_fd;
}


static int epoll_add(struct epl_thread *thread, int fd, uint32_t events,
		     epoll_data_t data)
{
	int ret;
	struct epoll_event evt;
	int epoll_fd = thread->epoll_fd;

	memset(&evt, 0, sizeof(evt));
	evt.events = events;
	evt.data = data;

	prl_notice(4, "[for thread %u] Adding fd (%d) to epoll_fd (%d)",
		   thread->idx, fd, epoll_fd);

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &evt);
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("epoll_ctl(%d, EPOLL_CTL_ADD, %d, events): " PRERF,
			epoll_fd, fd, PREAR(ret));
		ret = -ret;
	}

	return ret;
}


static int do_epoll_fd_registration(struct srv_udp_state *state,
				    struct epl_thread *thread)
{
	int ret;
	epoll_data_t data;
	int *tun_fds = state->tun_fds;
	const uint32_t events = EPOLLIN | EPOLLPRI;

	memset(&data, 0, sizeof(data));

	if (unlikely(state->cfg->sys.thread_num < 1)) {
		panic("Invalid thread num (%hhu)", state->cfg->sys.thread_num);
		__builtin_unreachable();
	}

	if (thread->idx == 0) {

		/*
		 * Main thread is responsible to handle data
		 * from UDP socket.
		 */
		data.fd = state->udp_fd;
		ret = epoll_add(thread, data.fd, events, data);
		if (unlikely(ret))
			return ret;

		if (state->cfg->sys.thread_num == 1) {
			/*
			 * If we are singlethreaded, the main thread
			 * is also responsible to read from TUN fd.
			 */
			data.fd = tun_fds[0];
			ret = epoll_add(thread, data.fd, events, data);
			if (unlikely(ret))
				return ret;
		}
	} else {
		data.fd = tun_fds[thread->idx];
		ret = epoll_add(thread, data.fd, events, data);
		if (unlikely(ret))
			return ret;

		if (thread->idx == 1) {
			/*
			 * If we are multithreaded, the subthread is responsible
			 * to read from tun_fds[0]. Don't give this work to the
			 * main thread for better concurrency.
			 */
			data.fd = tun_fds[0];
			ret = epoll_add(thread, data.fd, events, data);
			if (unlikely(ret))
				return ret;
		}
	}

	return 0;
}


static int init_epoll_thread(struct srv_udp_state *state,
			     struct epl_thread *thread)
{
	int ret;

	ret = create_epoll_fd();
	if (unlikely(ret < 0))
		return ret;

	thread->epoll_fd = ret;
	thread->epoll_timeout = 10000;

	ret = do_epoll_fd_registration(state, thread);
	if (unlikely(ret))
		return ret;

	return 0;
}


static int init_epoll_thread_array(struct srv_udp_state *state)
{
	int ret = 0;
	struct epl_thread *threads;
	uint8_t i, nn = state->cfg->sys.thread_num;

	state->epl_threads = NULL;
	threads = calloc_wrp((size_t)nn, sizeof(*threads));
	if (unlikely(!threads))
		return -errno;


	state->epl_threads = threads;

	/*
	 * Initialize all epoll_fd to -1 for graceful clean up in
	 * case we fail to create the epoll instance.
	 */
	for (i = 0; i < nn; i++) {
		threads[i].idx = i;
		threads[i].state = state;
		threads[i].epoll_fd = -1;
	}

	for (i = 0; i < nn; i++) {
		struct sc_pkt *pkt;

		ret = init_epoll_thread(state, &threads[i]);
		if (unlikely(ret))
			return ret;

		pkt = calloc_wrp(1ul, sizeof(*pkt));
		if (unlikely(!pkt))
			return -errno;

		threads[i].pkt = pkt;
	}

	return ret;
}


static int _do_epoll_wait(struct epl_thread *thread)
{
	int ret;
	int epoll_fd = thread->epoll_fd;
	int timeout = thread->epoll_timeout;
	struct epoll_event *events = thread->events;

	ret = epoll_wait(epoll_fd, events, EPOLL_EVT_ARR_NUM, timeout);
	if (unlikely(ret < 0)) {
		ret = errno;

		if (likely(ret == EINTR)) {
			prl_notice(2, "[thread=%u] Interrupted!", thread->idx);
			return 0;
		}

		pr_err("[thread=%u] epoll_wait(): " PRERF, thread->idx,
		       PREAR(ret));
		return -ret;
	}

	return ret;
}


static int close_udp_session(struct epl_thread *thread, struct udp_sess *sess)
{
	// size_t send_len;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	if (sess->ipv4_iff != 0)
		del_ipv4_route_map(thread->state->ipv4_map, sess->ipv4_iff);

	// send_len = srv_pprep(srv_pkt, TSRV_PKT_CLOSE, 0, 0);
	// send_to_client(thread, sess, srv_pkt, send_len);
	return put_udp_session(thread->state, sess);
}


static int handle_client_handshake(struct epl_thread *thread,
				   struct udp_sess *sess)
{
	return 0;
}


static int handle_new_client(struct epl_thread *thread,
			     struct srv_udp_state *state, uint32_t addr,
			     uint16_t port, struct sockaddr_in *saddr)
{
	int ret;
	struct udp_sess *sess;

	sess = get_udp_sess(thread->state, addr, port);
	if (unlikely(!sess))
		return -errno;

	sess->addr = *saddr;

#ifndef NDEBUG
	/*
	 * After calling get_udp_sess(), we must have it
	 * on the map. If we don't, then it's a bug!
	 */
	BUG_ON(map_find_udp_sess(state, addr, port) != sess);
#endif

	ret = handle_client_handshake(thread, sess);
	if (ret) {
		/*
		 * Handshake failed, drop the client session!
		 */
		close_udp_session(thread, sess);
		ret = (ret == -EBADMSG) ? 0 : ret;
	}

	return ret;
}


static int _handle_event_udp(struct epl_thread *thread,
			     struct srv_udp_state *state,
			     struct sockaddr_in *saddr)
{
	uint16_t port;
	uint32_t addr;
	struct udp_sess *sess;

	port = ntohs(saddr->sin_port);
	addr = ntohl(saddr->sin_addr.s_addr);
	sess = map_find_udp_sess(state, addr, port);
	if (unlikely(!sess)) {
		/*
		 * It's a new client since we don't find it in
		 * the session map.
		 */
		int ret = handle_new_client(thread, state, addr, port, saddr);
		return (ret == -EAGAIN) ? 0 : ret;
	}

	return 0;
}


static ssize_t do_recvfrom(struct epl_thread *thread,
			   int udp_fd, struct sockaddr_in *saddr,
			   socklen_t *saddr_len)
{
	int ret;
	ssize_t recv_ret;
	char *buf = thread->pkt->__raw;
	struct sockaddr *src_addr = (struct sockaddr *)saddr;
	const size_t recv_size = sizeof(thread->pkt->cli.__raw);

	recv_ret = recvfrom(udp_fd, buf, recv_size, 0, src_addr, saddr_len);
	if (unlikely(recv_ret <= 0)) {

		if (recv_ret == 0) {
			if (recv_size == 0)
				return 0;

			pr_err("UDP socket disconnected!");
			return -ENETDOWN;
		}

		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_err("recvfrom(udp_fd) (fd=%d): " PRERF, udp_fd, PREAR(ret));
		return -ret;
	}

	thread->pkt->len = (size_t)recv_ret;
	return recv_ret;
}


static int handle_event_udp(struct epl_thread *thread,
			    struct srv_udp_state *state, int udp_fd)
{
	ssize_t recv_ret;
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(saddr);

	recv_ret = do_recvfrom(thread, udp_fd, &saddr, &saddr_len);
	if (unlikely(recv_ret <= 0))
		return (int)recv_ret;

	return _handle_event_udp(thread, state, &saddr);
}


static int handle_event_tun(struct epl_thread *thread,
			    struct srv_udp_state *state, int udp_fd)
{
	return 0;
}


static int handle_event(struct epl_thread *thread, struct srv_udp_state *state,
			struct epoll_event *event)
{
	int ret = 0;
	int fd = event->data.fd;

	if (fd == thread->state->udp_fd) {
		ret = handle_event_udp(thread, state, fd);
	} else {
		ret = handle_event_tun(thread, state, fd);
	}

	return ret;
}


static int do_epoll_wait(struct epl_thread *thread, struct srv_udp_state *state)
{
	int ret, i, tmp;
	struct epoll_event *events;

	ret = _do_epoll_wait(thread);
	if (unlikely(ret < 0)) {
		pr_err("_do_epoll_wait(): " PRERF, PREAR(-ret));
		return ret;
	}

	events = thread->events;
	for (i = 0; i < ret; i++) {
		tmp = handle_event(thread, state, &events[i]);
		if (unlikely(tmp))
			return tmp;
	}

	return 0;
}


static void thread_wait(struct epl_thread *thread, struct srv_udp_state *state)
{
	static _Atomic(bool) release_sub_thread = false;
	uint8_t nn = state->cfg->sys.thread_num;

	if (thread->idx != 0) {
		/*
		 * We are the sub thread.
		 * Waiting for the main thread be ready...
		 */
		while (!atomic_load(&release_sub_thread)) {
			if (unlikely(state->stop))
				return;

			usleep(100000);
		}
		return;
	}

	/*
	 * We are the main thread. Wait for all threads
	 * to be spawned properly.
	 */
	while (atomic_load(&state->n_on_threads) != nn) {

		prl_notice(2, "(thread=%u) "
			   "Waiting for subthread(s) to be ready...",
			   thread->idx);

		if (unlikely(state->stop))
			return;

		usleep(100000);
	}

	if (nn > 1)
		prl_notice(2, "All threads are ready!");

	prl_notice(2, "Initialization Sequence Completed");
	atomic_store(&release_sub_thread, true);
}


__no_inline static void *_run_event_loop(void *thread_p)
{
	int ret = 0;
	struct epl_thread *thread;
	struct srv_udp_state *state;

	thread = (struct epl_thread *)thread_p;
	state  = thread->state;

	atomic_store(&thread->is_online, true);
	atomic_fetch_add(&state->n_on_threads, 1);
	thread_wait(thread, state);

	while (likely(!state->stop)) {
		ret = do_epoll_wait(thread, state);
		if (unlikely(ret)) {
			state->stop = true;
			break;
		}
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->n_on_threads, 1);
	return (void *)((intptr_t)ret);
}


static int spawn_thread(struct epl_thread *thread)
{
	int ret;

	prl_notice(2, "Spawning thread %u...", thread->idx);
	ret = pthread_create(&thread->thread, NULL, _run_event_loop, thread);
	if (unlikely(ret)) {
		pr_err("pthread_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = pthread_detach(thread->thread);
	if (unlikely(ret)) {
		pr_err("pthread_detach(): " PRERF, PREAR(ret));
		return -ret;
	}

	return ret;
}


static int run_event_loop(struct srv_udp_state *state)
{
	int ret;
	void *ret_p;
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	atomic_store(&state->n_on_threads, 0);
	for (i = 1; i < nn; i++) {
		/*
		 * Spawn the subthreads.
		 * 
		 * For @i == 0, it is the main thread,
		 * don't spawn pthread for it.
		 */
		ret = spawn_thread(&threads[i]);
		if (unlikely(ret))
			goto out;
	}

	ret_p = _run_event_loop(&threads[0]);
	ret   = (int)((intptr_t)ret_p);
out:
	return ret;
}


static bool wait_for_threads_to_exit(struct srv_udp_state *state)
{
	uint8_t nn, i;
	unsigned wait_c = 0;
	uint16_t thread_on = 0, cc;
	struct epl_thread *threads;

	thread_on = atomic_load(&state->n_on_threads);
	if (thread_on == 0)
		/*
		 * All threads have exited, it's good.
		 */
		return true;

	threads = state->epl_threads;
	nn = state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {
		int ret;

		if (!atomic_load(&threads[i].is_online))
			continue;

		ret = pthread_kill(threads[i].thread, SIGTERM);
		if (unlikely(ret)) {
			pr_err("pthread_kill(threads[%hhu].thread, SIGTERM): "
			       PRERF, i, PREAR(ret));
		}
	}

	prl_notice(2, "Waiting for %hu thread(s) to exit...", thread_on);
	while ((cc = atomic_load(&state->n_on_threads)) > 0) {

		if (cc != thread_on) {
			thread_on = cc;
			prl_notice(2, "Waiting for %hu thread(s) to exit...",
				   cc);
		}

		usleep(100000);
		if (wait_c++ > 1000)
			return false;
	}
	return true;
}


static void free_pkt_buffer(struct srv_udp_state *state)
{
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	if (unlikely(!threads))
		return;

	for (i = 0; i < nn; i++)
		al64_free(threads[i].pkt);
}


static void close_epoll_fds(struct srv_udp_state *state)
{
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	if (unlikely(!threads))
		return;

	for (i = 0; i < nn; i++) {
		int epoll_fd = threads[i].epoll_fd;

		if (epoll_fd == -1)
			continue;

		prl_notice(2, "Closing epoll_fd (fd=%d)...", epoll_fd);
		close(epoll_fd);
	}
}


static void destroy_epoll(struct srv_udp_state *state)
{
	if (!wait_for_threads_to_exit(state)) {
		/*
		 * Thread(s) won't exit, don't free the heap!
		 */
		pr_emerg("Thread(s) won't exit!");
		state->threads_wont_exit = true;
		return;
	}

	free_pkt_buffer(state);
	close_epoll_fds(state);
	al64_free(state->epl_threads);
}


int teavpn2_udp_server_epoll(struct srv_udp_state *state)
{
	int ret;

	ret = init_epoll_thread_array(state);
	if (unlikely(ret))
		goto out;

	state->stop = false;
	ret = run_event_loop(state);
out:
	destroy_epoll(state);
	return ret;
}
