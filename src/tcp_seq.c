#include "tcp_seq.h"

uint32_t tcp_translate_seq(
    uint32_t original_seq,
    int64_t offset
) {
    return original_seq + (uint32_t)offset;
}
int tcp_segment_mapping_init(
    TcpSegmentMapping *mapping,
    uint32_t original_seq,
    uint32_t translated_seq,
    uint32_t original_length,
    uint32_t encrypted_length
) {
    if (mapping == NULL || encrypted_length < original_length) {
        return 0;
    }

    mapping->original_seq = original_seq;
    mapping->translated_seq = translated_seq;
    mapping->original_length = original_length;
    mapping->encrypted_length = encrypted_length;

    return 1;
}
uint32_t tcp_segment_original_end(
    const TcpSegmentMapping *mapping
) {
    if (mapping == NULL) {
        return 0;
    }

    return mapping->original_seq + mapping->original_length;
}

uint32_t tcp_segment_translated_end(
    const TcpSegmentMapping *mapping
) {
    if (mapping == NULL) {
        return 0;
    }

    return mapping->translated_seq + mapping->encrypted_length;
}


const TcpSegmentMapping *tcp_find_segment(
    const TcpSegmentMapping *mappings,
    size_t count,
    uint32_t original_seq
) {
    if (mappings == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        if (mappings[i].original_seq == original_seq) {
            return &mappings[i];
        }
    }

    return NULL;
}

const TcpSegmentMapping *tcp_find_exact_segment(
    const TcpSegmentMapping *mappings,
    size_t count,
    uint32_t original_seq,
    uint32_t original_length
) {
    if (mappings == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        if (mappings[i].original_seq == original_seq &&
            mappings[i].original_length == original_length) {
            return &mappings[i];
        }
    }

    return NULL;
}
int tcp_segments_overlap(
    uint32_t seq1,
    uint32_t len1,
    uint32_t seq2,
    uint32_t len2
) {
    if (len1 == 0 || len2 == 0) {
        return 0;
    }

    uint32_t distance12 = seq2 - seq1;
    uint32_t distance21 = seq1 - seq2;

    return distance12 < len1 || distance21 < len2;
}
TcpSegmentStatus tcp_segment_table_add(
    TcpSegmentTable *table,
    uint32_t original_seq,
    uint32_t original_length,
    uint32_t encrypted_length,
    TcpSegmentMapping *result
) {
    if (table == NULL || result == NULL ||
        original_length == 0 ||
        encrypted_length < original_length ||
        table->count > TCP_MAX_SEGMENTS) {
        return TCP_SEGMENT_ERROR;
    }

    for (size_t i = 0; i < table->count; i++) {
        const TcpSegmentMapping *existing = &table->segments[i];

        if (existing->original_seq == original_seq &&
            existing->original_length == original_length &&
            existing->encrypted_length == encrypted_length) {
            *result = *existing;
            return TCP_SEGMENT_RETRANSMISSION;
        }

        if (tcp_segments_overlap(
                existing->original_seq,
                existing->original_length,
                original_seq,
                original_length)) {
            return TCP_SEGMENT_OVERLAP;
        }
    }

    if (table->count == TCP_MAX_SEGMENTS) {
        return TCP_SEGMENT_ERROR;
    }

    uint32_t translated_seq = original_seq;
    uint32_t offset = 0;

    for (size_t i = 0; i < table->count; i++) {
        const TcpSegmentMapping *existing = &table->segments[i];

        if ((int32_t)(original_seq -
            tcp_segment_original_end(existing)) >= 0) {
            offset += existing->encrypted_length -
                      existing->original_length;
        }
    }

    translated_seq += offset;

    TcpSegmentMapping *entry = &table->segments[table->count];

    if (!tcp_segment_mapping_init(
            entry,
            original_seq,
            translated_seq,
            original_length,
            encrypted_length)) {
        return TCP_SEGMENT_ERROR;
    }

    table->count++;
    *result = *entry;

    return TCP_SEGMENT_NEW;
}
