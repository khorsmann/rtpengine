#ifndef __CODEC_H__
#define __CODEC_H__


#include <glib.h>
#include <sys/time.h>
#include "str.h"
#include "codeclib.h"
#include "aux.h"
#include "rtplib.h"
#include "timerthread.h"


struct call_media;
struct codec_handler;
struct media_packet;
struct ssrc_hash;
struct sdp_ng_flags;
struct codec_ssrc_handler;
struct rtp_header;
struct stream_params;
struct supp_codec_tracker;
struct rtcp_timer;
struct mqtt_timer;
struct call;


typedef int codec_handler_func(struct codec_handler *, struct media_packet *);


struct codec_handler {
	struct rtp_payload_type source_pt; // source_pt.payload_type = hashtable index
	struct rtp_payload_type dest_pt;
	int dtmf_payload_type;
	int cn_payload_type;
	codec_handler_func *func;
	unsigned int kernelize:1;
	unsigned int transcoder:1;
	unsigned int dtmf_scaler:1;
	unsigned int pcm_dtmf_detect:1;

	struct ssrc_hash *ssrc_hash;
	struct codec_handler *output_handler; // == self, or other PT handler
	struct call_media *media;
#ifdef WITH_TRANSCODING
	int (*packet_encoded)(encoder_t *enc, void *u1, void *u2);
	int (*packet_decoded)(decoder_t *, AVFrame *, void *, void *);
#endif

	// for media playback
	struct codec_ssrc_handler *ssrc_handler;

	// stats entry
	char *stats_chain;
	struct codec_stats *stats_entry;
};

struct codec_packet {
	struct timerthread_queue_entry ttq_entry;
	str s;
	struct rtp_header *rtp;
	unsigned long ts;
	unsigned int clockrate;
	struct ssrc_ctx *ssrc_out;
	void (*free_func)(void *);
};


void codecs_init(void);
void codecs_cleanup(void);
void codec_timers_loop(void *);
void rtcp_timer_stop(struct rtcp_timer **);

void mqtt_timer_stop(struct mqtt_timer **);
void mqtt_timer_start(struct mqtt_timer **mqtp, struct call *call, struct call_media *media);

struct codec_handler *codec_handler_get(struct call_media *, int payload_type);
void codec_handlers_free(struct call_media *);
struct codec_handler *codec_handler_make_playback(const struct rtp_payload_type *src_pt,
		const struct rtp_payload_type *dst_pt, unsigned long ts, struct call_media *);
void ensure_codec_def(struct rtp_payload_type *pt, struct call_media *media);
void codec_calc_jitter(struct ssrc_ctx *, unsigned long ts, unsigned int clockrate, const struct timeval *);

void codec_add_raw_packet(struct media_packet *mp, unsigned int clockrate);
void codec_packet_free(void *);

void codec_rtp_payload_types(struct call_media *media, struct call_media *other_media,
		GQueue *types, struct sdp_ng_flags *flags);

// special return value `(void *) 0x1` to signal type mismatch
struct rtp_payload_type *codec_make_payload_type(const str *codec_str, struct call_media *media);
void codec_init_payload_type(struct rtp_payload_type *, struct call_media *);


// used by redis
void __rtp_payload_type_add_recv(struct call_media *media, struct rtp_payload_type *pt, int supp_check);
void __rtp_payload_type_add_send(struct call_media *other_media, struct rtp_payload_type *pt);



#ifdef WITH_TRANSCODING

void codec_handler_free(struct codec_handler **handler);
void codec_handlers_update(struct call_media *receiver, struct call_media *sink, const struct sdp_ng_flags *,
		const struct stream_params *);
void codec_add_dtmf_event(struct codec_ssrc_handler *ch, int code, int level, uint64_t ts);
uint64_t codec_last_dtmf_event(struct codec_ssrc_handler *ch);
uint64_t codec_encoder_pts(struct codec_ssrc_handler *ch);
void codec_decoder_skip_pts(struct codec_ssrc_handler *ch, uint64_t);
uint64_t codec_decoder_unskip_pts(struct codec_ssrc_handler *ch);
void codec_tracker_init(struct call_media *);
void codec_tracker_finish(struct call_media *, struct call_media *);
void codec_handlers_stop(GQueue *);

#else

INLINE void codec_handlers_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, const struct stream_params *sp) { }
INLINE void codec_handler_free(struct codec_handler **handler) { }
INLINE void codec_tracker_init(struct call_media *m) { }
INLINE void codec_tracker_finish(struct call_media *m, struct call_media *mm) { }
INLINE void codec_handlers_stop(GQueue *q) { }

#endif



#endif
