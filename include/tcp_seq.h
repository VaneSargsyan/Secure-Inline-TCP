#ifndef TCP_SEQ_H
#define TCP_SEQ_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t original_seq;
    uint32_t translated_seq;
    int64_t offset;
} TcpSeqMapping;

typedef struct {
    uint32_t original_seq;
    uint32_t translated_seq;
    uint32_t original_length;
    uint32_t encrypted_length;
} TcpSegmentMapping;

uint32_t tcp_translate_seq(
    uint32_t original_seq,
    int64_t offset
);
int tcp_segment_mapping_init(
    TcpSegmentMapping *mapping,
    uint32_t original_seq,
    uint32_t translated_seq,
    uint32_t original_length,
    uint32_t encrypted_length
);
uint32_t tcp_segment_original_end(
    const TcpSegmentMapping *mapping
);

uint32_t tcp_segment_translated_end(
    const TcpSegmentMapping *mapping
);
const TcpSegmentMapping *tcp_find_segment(
    const TcpSegmentMapping *mappings,
    size_t count,
    uint32_t original_seq
);
const TcpSegmentMapping *tcp_find_exact_segment(
    const TcpSegmentMapping *mappings,
    size_t count,
    uint32_t original_seq,
    uint32_t original_length
);

int tcp_segments_overlap(
    uint32_t seq1,
    uint32_t len1,
    uint32_t seq2,
    uint32_t len2
);
#define TCP_MAX_SEGMENTS 1024

typedef struct {
    TcpSegmentMapping segments[TCP_MAX_SEGMENTS];
    size_t count;
} TcpSegmentTable;

typedef enum {
    TCP_SEGMENT_ERROR = -1,
    TCP_SEGMENT_NEW = 0,
    TCP_SEGMENT_RETRANSMISSION = 1,
    TCP_SEGMENT_OVERLAP = 2
} TcpSegmentStatus;

TcpSegmentStatus tcp_segment_table_add(
    TcpSegmentTable *table,
    uint32_t original_seq,
    uint32_t original_length,
    uint32_t encrypted_length,
    TcpSegmentMapping *result
);
#endif
