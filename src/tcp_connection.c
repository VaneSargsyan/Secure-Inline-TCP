#include "tcp_connection.h"

#include <string.h>

int tcp_flow_equal(
    const TcpFlowKey *a,
    const TcpFlowKey *b
) {
    if (a == NULL || b == NULL) {
        return 0;
    }

    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port;
}

TcpConnection *tcp_connection_find(
    TcpConnectionTable *table,
    const TcpFlowKey *key
) {
    if (table == NULL || key == NULL ||
        table->count > TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    for (size_t i = 0; i < table->count; i++) {
        if (tcp_flow_equal(&table->connections[i].key, key)) {
            return &table->connections[i];
        }
    }

    return NULL;
}

TcpConnection *tcp_connection_add(
    TcpConnectionTable *table,
    const TcpFlowKey *key
) {
    if (table == NULL || key == NULL ||
        table->count > TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    TcpConnection *existing = tcp_connection_find(table, key);

    if (existing != NULL) {
        return existing;
    }

    if (table->count == TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    TcpConnection *connection = &table->connections[table->count++];

    memset(connection, 0, sizeof(*connection));

    connection->key = *key;
    connection->status = TCP_CONN_NEW;

    return connection;
}


int tcp_flow_reverse_equal(
    const TcpFlowKey *a,
    const TcpFlowKey *b
) {
    if (a == NULL || b == NULL) {
        return 0;
    }

    return a->src_ip == b->dst_ip &&
           a->dst_ip == b->src_ip &&
           a->src_port == b->dst_port &&
           a->dst_port == b->src_port;
}

TcpConnection *tcp_connection_find_bidirectional(
    TcpConnectionTable *table,
    const TcpFlowKey *key
) {
    if (table == NULL || key == NULL ||
        table->count > TCP_MAX_CONNECTIONS) {
        return NULL;
    }

    for (size_t i = 0; i < table->count; i++) {
        TcpConnection *connection = &table->connections[i];

        if (tcp_flow_equal(&connection->key, key) ||
            tcp_flow_reverse_equal(&connection->key, key)) {
            return connection;
        }
    }

    return NULL;
}
TcpDirection tcp_connection_direction(
    const TcpConnection *connection,
    const TcpFlowKey *key
) {
    if (connection == NULL || key == NULL) {
        return TCP_DIRECTION_INVALID;
    }

    if (tcp_flow_equal(&connection->key, key)) {
        return TCP_DIRECTION_FORWARD;
    }

    if (tcp_flow_reverse_equal(&connection->key, key)) {
        return TCP_DIRECTION_REVERSE;
    }

    return TCP_DIRECTION_INVALID;
}

TcpDirectionState *tcp_connection_direction_state(
    TcpConnection *connection,
    const TcpFlowKey *key
) {
    TcpDirection direction =
        tcp_connection_direction(connection, key);

    if (direction == TCP_DIRECTION_FORWARD) {
        return &connection->forward;
    }

    if (direction == TCP_DIRECTION_REVERSE) {
        return &connection->reverse;
    }

    return NULL;
}
int tcp_connection_process_event(
    TcpConnection *connection,
    TcpConnectionEvent event
) {
    if (connection == NULL) {
        return 0;
    }

    switch (connection->status) {
        case TCP_CONN_NEW:
            if (event == TCP_EVENT_SYN) {
                connection->status = TCP_CONN_SYN_SENT;
                return 1;
            }
            break;

        case TCP_CONN_SYN_SENT:
            if (event == TCP_EVENT_SYN_ACK) {
                connection->status = TCP_CONN_SYN_RECEIVED;
                return 1;
            }
            break;

        case TCP_CONN_SYN_RECEIVED:
            if (event == TCP_EVENT_ACK) {
                connection->status = TCP_CONN_ESTABLISHED;
                return 1;
            }
            break;

        case TCP_CONN_ESTABLISHED:
            if (event == TCP_EVENT_FIN) {
                connection->status = TCP_CONN_FIN_WAIT;
                return 1;
            }
            break;

        case TCP_CONN_FIN_WAIT:
            if (event == TCP_EVENT_ACK) {
                connection->status = TCP_CONN_CLOSING;
                return 1;
            }
            break;

        case TCP_CONN_CLOSING:
            if (event == TCP_EVENT_FIN) {
                connection->status = TCP_CONN_CLOSED;
                return 1;
            }
            break;

        case TCP_CONN_CLOSED:
            return 0;
    }

    if (event == TCP_EVENT_RST &&
        connection->status != TCP_CONN_CLOSED) {
        connection->status = TCP_CONN_CLOSED;
        return 1;
    }

    return 0;
}
