#include "tcp_seq.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    assert(tcp_translate_seq(1000, 28) == 1028);
    assert(tcp_translate_seq(1028, -28) == 1000);
    assert(tcp_translate_seq(UINT32_MAX, 1) == 0);
    assert(tcp_translate_seq(0, -1) == UINT32_MAX);
    assert(tcp_translate_seq(5000, 0) == 5000);

uint32_t encrypted_ack = 1128;
uint32_t original_ack = tcp_translate_seq(encrypted_ack, -28);

assert(original_ack == 1100);
TcpSegmentMapping mapping;

assert(tcp_segment_mapping_init(
    &mapping, 1000, 1000, 100, 128
) == 1);

assert(mapping.original_seq == 1000);
assert(mapping.translated_seq == 1000);
assert(mapping.original_length == 100);
assert(mapping.encrypted_length == 128);

assert(tcp_segment_mapping_init(
    &mapping, 1000, 1000, 128, 100
) == 0);

assert(tcp_segment_mapping_init(
    NULL, 1000, 1000, 100, 128
) == 0);
TcpSegmentMapping end_mapping;

assert(tcp_segment_mapping_init(
    &end_mapping, 1000, 1000, 100, 128
) == 1);

assert(tcp_segment_original_end(&end_mapping) == 1100);
assert(tcp_segment_translated_end(&end_mapping) == 1128);

assert(tcp_segment_original_end(NULL) == 0);
assert(tcp_segment_translated_end(NULL) == 0);
TcpSegmentMapping segments[2];

assert(tcp_segment_mapping_init(
    &segments[0], 1000, 1000, 100, 128
) == 1);

assert(tcp_segment_mapping_init(
    &segments[1], 1100, 1128, 100, 128
) == 1);

const TcpSegmentMapping *found =
    tcp_find_segment(segments, 2, 1000);

assert(found == &segments[0]);
assert(found->translated_seq == 1000);

found = tcp_find_segment(segments, 2, 1100);

assert(found == &segments[1]);
assert(found->translated_seq == 1128);

assert(tcp_find_segment(segments, 2, 1500) == NULL);
assert(tcp_find_segment(NULL, 2, 1000) == NULL);
const TcpSegmentMapping *retransmission =
    tcp_find_segment(segments, 2, 1000);

assert(retransmission != NULL);
assert(retransmission->original_length == 100);
assert(retransmission->encrypted_length == 128);

uint32_t incoming_length = 100;

assert(retransmission->original_length == incoming_length);

incoming_length = 50;

assert(retransmission->original_length != incoming_length);
const TcpSegmentMapping *exact =
    tcp_find_exact_segment(segments, 2, 1000, 100);

assert(exact == &segments[0]);

exact = tcp_find_exact_segment(segments, 2, 1100, 100);

assert(exact == &segments[1]);

assert(tcp_find_exact_segment(segments, 2, 1000, 50) == NULL);
assert(tcp_find_exact_segment(segments, 2, 1500, 100) == NULL);
assert(tcp_find_exact_segment(NULL, 2, 1000, 100) == NULL);
const TcpSegmentMapping *partial =
    tcp_find_exact_segment(segments, 2, 1050, 50);

assert(partial == NULL);
assert(tcp_segments_overlap(1000, 100, 1050, 50) == 1);
assert(tcp_segments_overlap(1000, 100, 1100, 100) == 0);
assert(tcp_segments_overlap(1000, 100, 1200, 50) == 0);
assert(tcp_segments_overlap(1000, 100, 1000, 100) == 1);
assert(tcp_segments_overlap(1050, 50, 1000, 100) == 1);
assert(tcp_segments_overlap(1000, 0, 1050, 50) == 0);
assert(tcp_segments_overlap(UINT32_MAX - 9, 20, 0, 5) == 1);  
assert(tcp_segments_overlap(UINT32_MAX - 4, 10, 0, 5) == 1);
assert(tcp_segments_overlap(0, 5, UINT32_MAX - 4, 10) == 1);
assert(tcp_segments_overlap(UINT32_MAX - 4, 5, 0, 5) == 0);
assert(tcp_segments_overlap(1000, 100, 900, 100) == 0);
assert(tcp_segments_overlap(1000, 100, 999, 1) == 0);
assert(tcp_segments_overlap(1000, 100, 0x80000000U, 100) == 0);
assert(tcp_segments_overlap(0, 100, 0x80000000U, 100) == 0);
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
) == TCP_SEGMENT_NEW);

assert(out_of_order.segments[0].translated_seq == 1100);
assert(out_of_order.segments[1].translated_seq == 1000);
  printf("All TCP sequence translation tests passed\n");

    return 0;
}
