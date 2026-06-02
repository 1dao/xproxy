#ifndef XCHANNEL_H
#define XCHANNEL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "xsock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xChannel xChannel;

typedef enum {
    XCHANNEL_FRAME_RAW = 0,
    XCHANNEL_FRAME_LEN32,
    XCHANNEL_FRAME_CRLF,
    XCHANNEL_FRAME_LEN16
} xChannelFrame;

typedef void (*xChannelConnectProc)(xChannel* ch, void* ud);

/* Framed modes ignore the return value. RAW mode uses it as the number of
** bytes consumed from the input buffer. Return 0 to keep all buffered data. 
** The data pointer is only valid during the callback. 
** Do not store it after the callback returns. Copy it if needed.
* */
typedef size_t (*xChannelPacketProc)(xChannel* ch, const char* data, size_t len, void* ud);

typedef void (*xChannelCloseProc)(xChannel* ch, const char* reason, void* ud);

/* recv_transform runs AFTER framing slices a packet and BEFORE packet_cb.
** send_transform runs BEFORE xchannel_send_packet prepends the length header.
**
** Both return 0 on success, negative on error (channel will close).
** On success, *out points to a malloc-allocated buffer; xchannel frees it
** after consumption. *out may be NULL only when *out_len is 0.
**
** The transform owns nothing about framing; xchannel owns the framing layer.
** Typical use: install an AEAD pair after handshake completes. */
typedef int (*xChannelRecvTransform)(xChannel* ch,
                                      const char* in, size_t in_len,
                                      char** out, size_t* out_len,
                                      void* ud);

typedef int (*xChannelSendTransform)(xChannel* ch,
                                      const char* in, size_t in_len,
                                      char** out, size_t* out_len,
                                      void* ud);

/* Called when the channel is closed/destroyed so the transform can free its
** per-channel state (keys, AEAD context, ...). May be NULL. */
typedef void (*xChannelTransformDtor)(void* ud);

typedef struct xChannelConfig {
    xChannelFrame       frame;

    /* Maximum packet size. 0 keeps the internal default (16 MB). */
    size_t              max_packet;

    xChannelConnectProc connect_cb;
    xChannelPacketProc  packet_cb;
    xChannelCloseProc   close_cb;

    void*               userdata;
} xChannelConfig;

#define XCHANNEL_CONFIG_INIT { XCHANNEL_FRAME_RAW, 0, NULL, NULL, NULL, NULL }

xChannel* xchannel_create(SOCKET_T fd, const xChannelConfig* cfg);
void      xchannel_destroy(xChannel* ch);

SOCKET_T  xchannel_fd(xChannel* ch);
bool      xchannel_is_closed(xChannel* ch);
bool      xchannel_is_connected(xChannel* ch);

void      xchannel_set_userdata(xChannel* ch, void* ud);
void*     xchannel_get_userdata(xChannel* ch);
void      xchannel_set_max_packet(xChannel* ch, size_t max_packet);

/* Per-direction backpressure limits (default 8 MB each).
** Send: when send buffer >= max, send_* return -2.
** Recv: when recv buffer > max, READABLE is suspended until process_input
**       drains it back below max. */
void      xchannel_set_max_send(xChannel* ch, size_t max);
void      xchannel_set_max_recv(xChannel* ch, size_t max);

void      xchannel_get_stats(xChannel* ch,
                              size_t* send_buf, size_t* recv_buf,
                              uint64_t* bytes_sent, uint64_t* bytes_recv);

int       xchannel_set_framing(xChannel* ch, const xChannelConfig* cfg);

/* Install (or clear, with NULL transforms) the per-channel transform pair.
** Both directions must be set together to keep the wire symmetric. The
** transform_ud and transform_dtor pair holds optional per-channel state
** that the transforms need (AEAD keys, sequence counters, ...).
** Passing recv=NULL and send=NULL clears the transforms; if a previous
** dtor was installed it is invoked. */
void      xchannel_set_transform(xChannel* ch,
                                  xChannelRecvTransform recv,
                                  xChannelSendTransform send,
                                  void* transform_ud,
                                  xChannelTransformDtor transform_dtor);

int       xchannel_attach(xChannel* ch);
int       xchannel_attach_connect(xChannel* ch);
void      xchannel_detach(xChannel* ch);

/* Detach from xpoll and surrender ownership of the underlying fd to the
** caller. Returns the original fd, or INVALID_SOCKET_VAL if the channel is
** already closed. After this call:
**   - ch->fd is set to INVALID_SOCKET_VAL
**   - the channel is marked closed (further sends fail)
**   - xchannel_destroy will NOT close the fd
** Typical use: an admission thread reads a handshake, decides routing, and
** then hands the raw fd to another thread for re-attach via xchannel_create
** + xchannel_attach. */
SOCKET_T  xchannel_release_fd(xChannel* ch);

int       xchannel_send_raw(xChannel* ch, const char* data, size_t len);
int       xchannel_send_packet(xChannel* ch, const char* data, size_t len);
int       xchannel_send_file_raw(xChannel* ch,
                                  const char* header, size_t header_len,
                                  const char* path,
                                  long long offset, long long length);
void      xchannel_close(xChannel* ch, const char* reason);
int       xchannel_close_after_flush(xChannel* ch, const char* reason);

#ifdef __cplusplus
}
#endif

#endif /* XCHANNEL_H */
