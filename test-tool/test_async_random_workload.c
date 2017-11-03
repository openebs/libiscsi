/*
   Copyright (C) SUSE LINUX GmbH 2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <signal.h>
#include <poll.h>

#include <CUnit/CUnit.h>

#include "iscsi.h"
#include "iscsi-private.h"
#include "scsi-lowlevel.h"
#include "iscsi-support.h"
#include "iscsi-test-cu.h"

static uint32_t usent = 0;
static uint32_t udone = 0;

struct tests_async_random_abort_state {
	struct scsi_task *wtask;
	uint32_t aborted;
	uint32_t wr_cancelled;
	uint32_t wr_good;
	uint32_t abort_ok;
	uint32_t abort_bad_itt;
};

int read_percent = 0;
int write_percent = 100;

int abort_percent = 90;

int big_io_percent = 80;

int reset_offset_percent = 5;

#define READ 0
#define WRITE 1

#define NOT_ABORT_IO 0
#define ABORT_IO 1

#define SMALL_IO 0
#define BIG_IO 1

#define RESET_OFFSET 0
#define CONT_OFFSET 1

int get_iotype(void);
int get_offsetflag(void);
int get_iolen(void);
int get_abortflag(void);

int get_iotype()
{
	int r = rand()%100;

	if(r<read_percent)
		return READ;
	else if((r+read_percent) < write_percent)
		return WRITE;
	else
		return WRITE;
}

int get_abortflag()
{
	int r = rand()%100;

	if(r<abort_percent)
		return ABORT_IO;
	else
		return NOT_ABORT_IO;
}

int get_iolen()
{
	int r = rand() % 100;

	if(r<big_io_percent)
		return BIG_IO;
	else
		return SMALL_IO;
}

int get_offsetflag()
{
	int r = rand() % 100;

	if(r<reset_offset_percent)
		return RESET_OFFSET;
	else
		return CONT_OFFSET;
}


static void
test_async_random_write_cb(struct iscsi_context *iscsi __attribute__((unused)),
		    int status, void *command_data,
		    void *private_data)
{
	struct scsi_task *wtask = command_data;
	struct tests_async_random_abort_state *state = private_data;

	if (status == SCSI_STATUS_GOOD) {
		state->wr_good++;
		logging(LOG_VERBOSE, "WRITE10 successful: (CmdSN=0x%x, "
			"ITT=0x%x wMaxcmdSN=0x%x wstatsn:0x%x maxcmdsn:0x%x statsn:0x%x)", wtask->cmdsn, wtask->itt,
			wtask->maxcmdsn, wtask->statsn, iscsi->maxcmdsn, iscsi->statsn);
	} else if (status == SCSI_STATUS_CANCELLED) {
		state->wr_cancelled++;
		logging(LOG_VERBOSE, "WRITE10 cancelled: (CmdSN=0x%x, "
			"ITT=0x%x MaxcmdSN=0x%x)", wtask->cmdsn, wtask->itt,
			iscsi->maxcmdsn);
	} else {
		printf("writecb: status: %d CmdSN=0x%x ITT=0x%x wMaxcmdSN=0x%x wstatsn:0x%x maxcmdsn:0x%x statsn:0x%x\n",
				status, wtask->cmdsn, wtask->itt, wtask->maxcmdsn, wtask->statsn,
				iscsi->maxcmdsn, iscsi->statsn);
		CU_ASSERT_NOT_EQUAL(status, SCSI_STATUS_CHECK_CONDITION);
		return;
	}

	if(state->aborted == 0)
	{
		udone++;
		free(state);
	}
}

static void
test_async_random_abort_cb(struct iscsi_context *iscsi __attribute__((unused)),
		    int status, void *command_data,
		    void *private_data)
{
	uint32_t tmf_response;
	struct tests_async_random_abort_state *state = private_data;

	/* command_data NULL if a reconnect occured. see iscsi_reconnect_cb() */
	CU_ASSERT_PTR_NOT_NULL_FATAL(command_data);
	tmf_response = *(uint32_t *)command_data;

	logging(LOG_VERBOSE, "ABORT TASK: TMF response %d for"
		" RefCmdSN=0x%x, RefITT=0x%x wMaxcmdSN=0x%x wstatsn:0x%x maxcmdsn:0x%x statsn:0x%x",
		tmf_response, state->wtask->cmdsn, state->wtask->itt,
		state->wtask->maxcmdsn, state->wtask->statsn,
		iscsi->maxcmdsn, iscsi->statsn);
	if (tmf_response == ISCSI_TMR_FUNC_COMPLETE) {
		state->abort_ok++;
		logging(LOG_VERBOSE, "ABORT TASK completed");
	} else if (tmf_response == ISCSI_TMR_TASK_DOES_NOT_EXIST) {
		/* expected if the write has already been handled by the tgt */
		state->abort_bad_itt++;
		logging(LOG_VERBOSE, "ABORT TASK bad ITT");
	} else {
		logging(LOG_NORMAL, "ABORT TASK: unexpected TMF response %d for"
			" RefCmdSN=0x%x, RefITT=0x%x",
			tmf_response, state->wtask->cmdsn, state->wtask->itt);
		CU_ASSERT_FATAL((tmf_response != ISCSI_TMR_FUNC_COMPLETE)
			    && (tmf_response != ISCSI_TMR_TASK_DOES_NOT_EXIST));
	}
	CU_ASSERT_NOT_EQUAL(status, SCSI_STATUS_CHECK_CONDITION);
	udone++;
	free(state);
}

void
test_async_random_workload(void)
{
	int ret;
	struct tests_async_random_abort_state *pstate;
	int blocksize = 512;
	int blocks_per_io = 2048;
	uint64_t timeout_sec, now, runtime, elapsed_time;
	int offset = 0;
	uint64_t initial_maxcmdsn;
	uint64_t initial_cmdsn;
	unsigned char *buf;

	srand(time(NULL));
	usent = udone = 0;
	buf = (unsigned char *)malloc(blocksize*blocks_per_io);
	CU_ASSERT_PTR_NOT_NULL_FATAL(buf);
	memset(buf, 0, blocksize*blocks_per_io);

	printf("sending write..\n");
	CHECK_FOR_DATALOSS;
	CHECK_FOR_SBC;
	if (sd->iscsi_ctx == NULL) {
                CU_PASS("[SKIPPED] Non-iSCSI");
		return;
	}

	if (maximum_transfer_length
	 && (maximum_transfer_length < (int)(blocks_per_io))) {
		CU_PASS("[SKIPPED] device too small for async_abort test");
		return;
	}

	initial_cmdsn = sd->iscsi_ctx->cmdsn;
	initial_maxcmdsn = sd->iscsi_ctx->maxcmdsn;

	now = test_get_clock_sec();
	runtime = 30;
	elapsed_time =0;

	while(elapsed_time < runtime)
	{
		int iotype = get_iotype();
		int abort_or_not = get_abortflag();
		int io_len = get_iolen();
		int offset_flag = get_offsetflag();

		blocks_per_io = 8;
		int abort = 0;

		/* this is to avoid crashes due to aborts towards the end of the test */
		if(elapsed_time > (runtime - 3))
		{
			abort_or_not = NOT_ABORT_IO;
			io_len = SMALL_IO;
		}

		switch(offset_flag)
		{
			case RESET_OFFSET:
				offset = 0;
				break;
		}
		switch(io_len)
		{
			case BIG_IO:
				blocks_per_io = 2048;
				break;
			case SMALL_IO:
				blocks_per_io = 8;
				break;
		}
		switch(abort_or_not)
		{
			case ABORT_IO:
				abort = 1;
				break;
			case NOT_ABORT_IO:
				abort = 0;
				break;
		}
		pstate = malloc(sizeof(struct tests_async_random_abort_state));
		memset(pstate, 0, (sizeof(struct tests_async_random_abort_state)));
		switch(iotype)
		{
			case WRITE:
				pstate->wtask = scsi_cdb_write10(offset, blocks_per_io * blocksize,
					 blocksize, 0, 0, 0, 0, 0);

				CU_ASSERT_PTR_NOT_NULL_FATAL(pstate->wtask);

				ret = scsi_task_add_data_out_buffer(pstate->wtask,
					    blocks_per_io * blocksize, buf);
				CU_ASSERT_EQUAL(ret, 0);

				ret = iscsi_scsi_command_async(sd->iscsi_ctx, sd->iscsi_lun,
				       pstate->wtask, test_async_random_write_cb, NULL, pstate);
				CU_ASSERT_EQUAL(ret, 0);
				break;
		}

		logging(LOG_VERBOSE, "WRITE10 queued: (CmdSN=0x%x, ITT=0x%x MaxCmdSN=0x%x statsn:0x%x abort:%d bigio:%d offset: %d)",
			pstate->wtask->cmdsn, pstate->wtask->itt, sd->iscsi_ctx->maxcmdsn, sd->iscsi_ctx->statsn, abort, blocks_per_io, offset);
		offset += (blocks_per_io);

		usent++;
		if(abort == 1)
			pstate->aborted = 1;

		while ((uint32_t)iscsi_out_queue_length(sd->iscsi_ctx) > 0) {
			struct pollfd pfd;

			pfd.fd = iscsi_get_fd(sd->iscsi_ctx);

			pfd.events = iscsi_which_events(sd->iscsi_ctx);

			ret = poll(&pfd, 1, 1000);
			CU_ASSERT_NOT_EQUAL(ret, -1);

			ret = iscsi_service(sd->iscsi_ctx, pfd.revents);
			CU_ASSERT_EQUAL(ret, 0);
		
			pfd.events = POLLOUT;	/* only send */

			ret = poll(&pfd, 1, 1000);
			CU_ASSERT_NOT_EQUAL(ret, -1);

			ret = iscsi_service(sd->iscsi_ctx, pfd.revents);
			CU_ASSERT_EQUAL(ret, 0);
		}

		if(abort == 0)
			continue;

		logging(LOG_VERBOSE, "Sending abort 0x%x for 0x%x statsn:0x%x maxcmd:0x%x", sd->iscsi_ctx->cmdsn, pstate->wtask->cmdsn,
				sd->iscsi_ctx->statsn, sd->iscsi_ctx->maxcmdsn);
		ret = iscsi_task_mgmt_async(sd->iscsi_ctx,
					    pstate->wtask->lun, ISCSI_TM_ABORT_TASK,
					    pstate->wtask->itt, pstate->wtask->cmdsn,
					    test_async_random_abort_cb, pstate);
		CU_ASSERT_EQUAL(ret, 0);

		elapsed_time = (test_get_clock_sec() - now);

	}

	timeout_sec = test_get_clock_sec() + 35;
	while (test_get_clock_sec() <= timeout_sec) {
		struct pollfd pfd;

		pfd.fd = iscsi_get_fd(sd->iscsi_ctx);
		pfd.events = iscsi_which_events(sd->iscsi_ctx);

		ret = poll(&pfd, 1, 1000);
		CU_ASSERT_NOT_EQUAL(ret, -1);

		ret = iscsi_service(sd->iscsi_ctx, pfd.revents);
		CU_ASSERT_EQUAL(ret, 0);

		if(udone >= usent)
			break;
	}

	printf("i_mx:0x%lx cmdsn:0x%x mx:0x%x s:%d d:%d\n", initial_maxcmdsn, sd->iscsi_ctx->cmdsn, sd->iscsi_ctx->maxcmdsn, usent, udone);

	CU_ASSERT_EQUAL((initial_maxcmdsn-initial_cmdsn), (sd->iscsi_ctx->maxcmdsn - sd->iscsi_ctx->cmdsn));
	free(buf);

	/* Avoid that callbacks get invoked after this test finished */
        iscsi_logout_sync(sd->iscsi_ctx);
        iscsi_destroy_context(sd->iscsi_ctx);
	sd->iscsi_ctx = NULL;
}
