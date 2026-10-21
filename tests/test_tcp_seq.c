
#include "tcp_seq.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    assert(tcp_translate_seq(1000, 28) == 1028);
    assert(tcp_translate_seq(1028, -28) == 1000);
    assert(tcp_translate_seq(UINT32_MAX, 1) == 0);

    TcpSegmentMapping segment;

    assert(tcp_segment_mapping_init(
        &segment, 1000, 1000, 100, 128
    ) == 1);

    assert(segment.original_seq == 1000);
    assert(segment.translated_seq == 1000);
    assert(segment.original_length == 100);
    assert(segment.encrypted_length == 128);
    assert(tcp_segment_original_end(&segment) == 1100);
    assert(tcp_segment_translated_end(&segment) == 1128);

    assert(tcp_segment_mapping_init(
        NULL, 1000, 1000, 100, 128
    ) == 0);

    assert(tcp_segment_mapping_init(
        &segment, 1000, 1000, 100, 99
    ) == 0);

    assert(tcp_segment_original_end(NULL) == 0);
    assert(tcp_segment_translated_end(NULL) == 0);

    TcpSegmentMapping segments[2];

    assert(tcp_segment_mapping_init(
        &segments[0], 1000, 1000, 100, 128
    ) == 1);

    assert(tcp_segment_mapping_init(
        &segments[1], 1100, 1128, 100, 128
    ) == 1);

    assert(tcp_find_segment(
        segments, 2, 1000
    ) == &segments[0]);

    assert(tcp_find_segment(
        segments, 2, 1100
    ) == &segments[1]);

    assert(tcp_find_segment(
        segments, 2, 5000
    ) == NULL);

    assert(tcp_find_segment(
        NULL, 2, 1000
    ) == NULL);

    assert(tcp_find_exact_segment(
        segments, 2, 1000, 100
    ) == &segments[0]);

    assert(tcp_find_exact_segment(
        segments, 2, 1000, 50
    ) == NULL);

    assert(tcp_segments_overlap(1000, 100, 1050, 100) == 1);
    assert(tcp_segments_overlap(1000, 100, 1100, 100) == 0);
    assert(tcp_segments_overlap(1000, 100, 900, 150) == 1);
    assert(tcp_segments_overlap(1000, 0, 1000, 100) == 0);
    assert(tcp_segments_overlap(UINT32_MAX - 5, 10, 0, 4) == 1);

    TcpSegmentTable table = {0};
    TcpSegmentMapping entry;

    assert(tcp_segment_table_add(
        &table, 1000, 100, 128, &entry
    ) == TCP_SEGMENT_NEW);

    assert(entry.translated_seq == 1000);
    assert(table.count == 1);

    assert(tcp_segment_table_add(
        &table, 1100, 100, 128, &entry
    ) == TCP_SEGMENT_NEW);

    assert(entry.translated_seq == 1128);
    assert(table.count == 2);

    assert(tcp_segment_table_add(
        &table, 1000, 100, 128, &entry
    ) == TCP_SEGMENT_RETRANSMISSION);

    assert(entry.translated_seq == 1000);
    assert(table.count == 2);

    assert(tcp_segment_table_add(
        &table, 1050, 50, 78, &entry
    ) == TCP_SEGMENT_OVERLAP);

    assert(table.count == 2);

    TcpSegmentTable out_of_order = {0};
    TcpSegmentMapping out_entry;

    assert(tcp_segment_table_add(
        &out_of_order, 1100, 100, 128, &out_entry
    ) == TCP_SEGMENT_NEW);

    assert(tcp_segment_table_add(
        &out_of_order, 1000, 100, 128, &out_entry
    ) == TCP_SEGMENT_ERROR);

    assert(out_of_order.count == 1);
    assert(out_of_order.segments[0].translated_seq == 1100);

    TcpSegmentTable ack_table = {0};
    TcpSegmentMapping ack_segment;
    uint32_t original_ack = 0;

    assert(tcp_segment_table_add(
        &ack_table, 1000, 100, 128, &ack_segment
    ) == TCP_SEGMENT_NEW);

    assert(tcp_translate_ack(
        &ack_table, 1128, &original_ack
    ) == TCP_ACK_MAPPED);

    assert(original_ack == 1100);

    assert(tcp_segment_table_add(
        &ack_table, 1100, 100, 128, &ack_segment
    ) == TCP_SEGMENT_NEW);

    assert(tcp_translate_ack(
        &ack_table, 1256, &original_ack
    ) == TCP_ACK_MAPPED);

    assert(original_ack == 1200);

    assert(tcp_translate_ack(
        &ack_table, 1050, &original_ack
    ) == TCP_ACK_INSIDE_SEGMENT);

    assert(tcp_translate_ack(
        &ack_table, 5000, &original_ack
    ) == TCP_ACK_UNMAPPED);

    assert(tcp_translate_ack(
        &ack_table, 1000, &original_ack
    ) == TCP_ACK_UNMAPPED);

    assert(tcp_translate_ack(
        NULL, 1128, &original_ack
    ) == TCP_ACK_UNMAPPED);

    assert(tcp_translate_ack(
        &ack_table, 1128, NULL
    ) == TCP_ACK_UNMAPPED);

    TcpSegmentTable wrap_table = {0};
    TcpSegmentMapping wrap_segment;

    assert(tcp_segment_table_add(
        &wrap_table, UINT32_MAX - 15, 20, 48, &wrap_segment
    ) == TCP_SEGMENT_NEW);

    assert(tcp_translate_ack(
        &wrap_table, 32, &original_ack
    ) == TCP_ACK_MAPPED);

    assert(original_ack == 4);

    TcpSegmentTable order_table = {0};
    TcpSegmentMapping order_mapping;

    assert(tcp_segment_table_add(
        &order_table, 1100, 100, 128, &order_mapping
    ) == TCP_SEGMENT_NEW);

    assert(order_mapping.translated_seq == 1100);

    assert(tcp_segment_table_add(
        &order_table, 1000, 100, 128, &order_mapping
    ) == TCP_SEGMENT_ERROR);

    assert(order_table.count == 1);
    assert(order_table.segments[0].translated_seq == 1100);

    TcpSegmentTable retrans_table = {0};
    TcpSegmentMapping retrans_mapping;

    assert(tcp_segment_table_add(
        &retrans_table, 2000, 100, 128, &retrans_mapping
    ) == TCP_SEGMENT_NEW);

    assert(retrans_mapping.translated_seq == 2000);
    assert(retrans_table.count == 1);

    assert(tcp_segment_table_add(
        &retrans_table, 2000, 100, 128, &retrans_mapping
    ) == TCP_SEGMENT_RETRANSMISSION);

    assert(retrans_mapping.translated_seq == 2000);
    assert(retrans_table.count == 1);

    assert(tcp_segment_table_add(
        &retrans_table, 2050, 100, 128, &retrans_mapping
    ) == TCP_SEGMENT_OVERLAP);

    assert(retrans_table.count == 1);

    assert(tcp_segment_table_add(
        &retrans_table, 2100, 100, 128, &retrans_mapping
    ) == TCP_SEGMENT_NEW);

    assert(retrans_mapping.translated_seq == 2128);
    assert(retrans_table.count == 2);

    TcpSegmentTable ordered_table = {0};
    TcpSegmentMapping ordered_mapping;

    assert(tcp_segment_table_add(
        &ordered_table, 1100, 100, 128, &ordered_mapping
    ) == TCP_SEGMENT_NEW);

    assert(tcp_segment_table_add(
        &ordered_table, 1000, 100, 128, &ordered_mapping
    ) == TCP_SEGMENT_ERROR);

    assert(ordered_table.count == 1);

TcpSegmentTable recovery_table = {0};
TcpSegmentMapping recovery_mapping;

assert(tcp_segment_table_add(
    &recovery_table, 1000, 100, 128, &recovery_mapping
) == TCP_SEGMENT_NEW);

assert(tcp_segment_table_add(
    &recovery_table, 900, 100, 128, &recovery_mapping
) == TCP_SEGMENT_ERROR);

assert(recovery_table.count == 1);

assert(tcp_segment_table_add(
    &recovery_table, 1100, 100, 128, &recovery_mapping
) == TCP_SEGMENT_NEW);

assert(recovery_mapping.translated_seq == 1128);
assert(recovery_table.count == 2);

    printf("All TCP sequence translation tests passed\n");

    return 0;
}
