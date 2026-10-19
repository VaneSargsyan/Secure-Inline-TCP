
#include "tcp_connection.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
    static TcpConnectionTable table = {0};

    TcpFlowKey flow1 = {
        .src_ip = 0x0A000101,
        .dst_ip = 0x0A000302,
        .src_port = 45000,
        .dst_port = 5000
    };

    TcpFlowKey flow2 = {
        .src_ip = 0x0A000101,
        .dst_ip = 0x0A000302,
        .src_port = 45001,
        .dst_port = 5000
    };

    TcpFlowKey reverse_flow = {
        .src_ip = 0x0A000302,
        .dst_ip = 0x0A000101,
        .src_port = 5000,
        .dst_port = 45000
    };

    assert(tcp_flow_equal(&flow1, &flow1) == 1);
    assert(tcp_flow_equal(&flow1, &flow2) == 0);
    assert(tcp_flow_reverse_equal(&flow1, &reverse_flow) == 1);
    assert(tcp_flow_reverse_equal(&flow1, &flow2) == 0);

    TcpConnection *first = tcp_connection_add(&table, &flow1);

    assert(first != NULL);
    assert(first->status == TCP_CONN_NEW);
    assert(table.count == 1);

    assert(tcp_connection_find(&table, &flow1) == first);
    assert(tcp_connection_add(&table, &flow1) == first);
    assert(table.count == 1);

    TcpConnection *second = tcp_connection_add(&table, &flow2);

    assert(second != NULL);
    assert(second != first);
    assert(table.count == 2);

    assert(tcp_connection_find_bidirectional(&table, &flow1) == first);
    assert(tcp_connection_find_bidirectional(&table, &reverse_flow) == first);
    assert(tcp_connection_find_bidirectional(&table, &flow2) == second);

    assert(tcp_connection_find(&table, NULL) == NULL);
    assert(tcp_connection_add(NULL, &flow1) == NULL);

    assert(tcp_connection_direction(
        first, &flow1
    ) == TCP_DIRECTION_FORWARD);

    assert(tcp_connection_direction(
        first, &reverse_flow
    ) == TCP_DIRECTION_REVERSE);

    assert(tcp_connection_direction(
        first, &flow2
    ) == TCP_DIRECTION_INVALID);

    TcpDirectionState *forward =
        tcp_connection_direction_state(first, &flow1);

    TcpDirectionState *reverse =
        tcp_connection_direction_state(first, &reverse_flow);

    assert(forward != NULL);
    assert(reverse != NULL);
    assert(forward != reverse);

    forward->initial_seq = 1000;
    reverse->initial_seq = 5000;

    assert(first->forward.initial_seq == 1000);
    assert(first->reverse.initial_seq == 5000);

    TcpSegmentMapping mapping;

    assert(tcp_segment_table_add(
        &forward->segments, 1000, 100, 128, &mapping
    ) == TCP_SEGMENT_NEW);

    assert(forward->segments.count == 1);
    assert(reverse->segments.count == 0);

    static TcpConnectionTable lifecycle_table = {0};

    TcpConnection *lifecycle =
        tcp_connection_add(&lifecycle_table, &flow1);

    assert(lifecycle != NULL);
    assert(lifecycle->status == TCP_CONN_NEW);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_ACK
    ) == 0);

    assert(lifecycle->status == TCP_CONN_NEW);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_SYN
    ) == 1);

    assert(lifecycle->status == TCP_CONN_SYN_SENT);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_SYN_ACK
    ) == 1);

    assert(lifecycle->status == TCP_CONN_SYN_RECEIVED);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_ACK
    ) == 1);

    assert(lifecycle->status == TCP_CONN_ESTABLISHED);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_FIN
    ) == 1);

    assert(lifecycle->status == TCP_CONN_FIN_WAIT);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_ACK
    ) == 1);

    assert(lifecycle->status == TCP_CONN_CLOSING);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_FIN
    ) == 1);

    assert(lifecycle->status == TCP_CONN_CLOSED);

    assert(tcp_connection_process_event(
        lifecycle, TCP_EVENT_ACK
    ) == 0);

    assert(tcp_connection_process_event(
        NULL, TCP_EVENT_SYN
    ) == 0);

    printf("All TCP connection tests passed\n");

    return 0;
}
