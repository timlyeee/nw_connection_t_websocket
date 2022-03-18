/*
 Start a websocket link to input address, program will open a small chat room
 endpoint to endpoint. Only send and receive functionality is enabled. This demo
 is modified based on Apple's demo
 https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework?language=objc
 Thanks to the solution from forum answer:
 https://developer.apple.com/forums/thread/693799
 */

#include "Network/Network.h"
#include <err.h>
#include <string>

const char *hostname{"127.0.0.1"};
const char *hostport{"8080"};

char *g_psk = nullptr;        // TLS_PSK.
char *g_local_port = nullptr; // Local port, use as inbound endpoint (Listener)
char *g_local_address =
    nullptr;             // Local address, use as inbound endpoint (Listener)
bool g_listener = false; // Create connection as listener.
bool g_use_udp = false;  // Connect with tcp if false.
bool g_use_tls = false;
int g_family = AF_UNSPEC; // FreeBSD address family

extern "C" {
#define DEBUG 1
#if DEBUG == 1
#define NWLOG(format, ...) printf(format, ##__VA_ARGS__)
#else
#define NWLOG(format, ...)
#endif
}
// Create client side websocket connection
nw_connection_t create_ws_connection(const char *address, const char *port);
// Start connection, if listener, start listening
void start_connection(nw_connection_t connection);
void send_loop(nw_connection_t connection);
void receive_loop(nw_connection_t connection);
void start_send_receive_loop(nw_connection_t connection);

int main(int argc, const char *argv[]) {
  nw_connection_t connection = create_ws_connection(hostname, hostport);
  if (connection == NULL) {
    err(1, NULL);
  }
  start_connection(connection);
  NWLOG("start connection successed\n");
  start_send_receive_loop(connection);
  dispatch_main();
  // Unreachable
}

nw_connection_t create_ws_connection(const char *address, const char *port) {
  std::string sock_address_url =
      "ws://" + std::string(address) + ":" + std::string(port);
  const char *sock_address_url_c = sock_address_url.c_str();
  // TODO: dynamically change g_family
  g_family = AF_INET;

  nw_endpoint_t endpoint;
  if (g_listener) {
    NWLOG("start websocket listener on %s\n", sock_address_url_c);
    endpoint = nw_endpoint_create_host(address, port);
  } else {
    NWLOG("start websocket client side to url %s\n", sock_address_url_c);
    endpoint = nw_endpoint_create_url(sock_address_url_c);
  }

  nw_endpoint_type_t endpoint_type = nw_endpoint_get_type(endpoint);
  NWLOG("endpoint type is %d \n", endpoint_type);

  nw_parameters_configure_protocol_block_t configure_tls{
      NW_PARAMETERS_DISABLE_PROTOCOL};
  if (g_use_tls) {
    if (g_psk) {
      configure_tls = ^(nw_protocol_options_t tls_options) {
        sec_protocol_options_t sec_options =
            nw_tls_copy_sec_protocol_options(tls_options);
        dispatch_data_t psk = dispatch_data_create(
            g_psk, strlen(g_psk), nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        sec_protocol_options_add_pre_shared_key(sec_options, psk, psk);
        dispatch_release(psk);
        sec_protocol_options_add_tls_ciphersuite(
            sec_options, (SSLCipherSuite)TLS_PSK_WITH_AES_128_GCM_SHA256);
        nw_release(sec_options);
      };
    }
  } else {
    // TODO: NW_PARAMETERS_DEFAULT_PROTOCOL shows error when connecting to local
    // port, use DISABLE_PROTOCOL instead, need a better way to configure it
    configure_tls = NW_PARAMETERS_DISABLE_PROTOCOL;
  }

  nw_parameters_t parameters;
  if (g_use_udp) {
    parameters = nw_parameters_create_secure_udp(
        configure_tls, NW_PARAMETERS_DEFAULT_CONFIGURATION);
  } else {
    parameters = nw_parameters_create_secure_tcp(
        configure_tls, NW_PARAMETERS_DEFAULT_CONFIGURATION);
  }
  nw_release(configure_tls);
  nw_protocol_stack_t protocol_stack =
      nw_parameters_copy_default_protocol_stack(parameters);
  if (g_family == AF_INET || g_family == AF_INET6) {
    nw_protocol_options_t websocket_options =
        nw_ws_create_options(nw_ws_version_13);
    nw_protocol_stack_prepend_application_protocol(protocol_stack,
                                                   websocket_options);
  }

  nw_parameters_set_local_endpoint(parameters, endpoint);
  nw_release(protocol_stack);
  nw_connection_t connection = nw_connection_create(endpoint, parameters);
  nw_release(endpoint);
  nw_release(parameters);
  return connection;
}
void start_connection(nw_connection_t connection) {
  nw_connection_set_queue(connection, dispatch_get_main_queue());
  nw_retain(connection); // Hold a reference until cancelled
  nw_connection_set_state_changed_handler(
      connection, ^(nw_connection_state_t state, nw_error_t error) {
        nw_endpoint_t remote = nw_connection_copy_endpoint(connection);
        errno = error ? nw_error_get_error_code(error) : 0;
        if (state == nw_connection_state_waiting) {
          NWLOG("connect to %s port %u (%s) failed, is waiting",
                nw_endpoint_get_hostname(remote), nw_endpoint_get_port(remote),
                g_use_udp ? "udp" : "tcp");
        } else if (state == nw_connection_state_failed) {
          NWLOG("connect to %s port %u (%s) failed",
                nw_endpoint_get_hostname(remote), nw_endpoint_get_port(remote),
                g_use_udp ? "udp" : "tcp");
        } else if (state == nw_connection_state_ready) {
          NWLOG("Connection to %s port %u (%s) succeeded!\n",
                nw_endpoint_get_hostname(remote), nw_endpoint_get_port(remote),
                g_use_udp ? "udp" : "tcp");
        } else if (state == nw_connection_state_cancelled) {
          // Release the primary reference on the connection
          // that was taken at creation time
          nw_release(connection);
        }
        nw_release(remote);
      });
  nw_connection_start(connection);
}
void send_loop(nw_connection_t connection) {
  dispatch_read(
      STDIN_FILENO, 8192, dispatch_get_main_queue(),
      ^(dispatch_data_t _Nonnull read_data, int stdin_error) {
        if (stdin_error != 0) {
          errno = stdin_error;
          NWLOG("stdin read error");
        } else if (read_data == NULL) {
          nw_connection_send(connection, NULL,
                             NW_CONNECTION_FINAL_MESSAGE_CONTEXT, true,
                             ^(nw_error_t _Nullable error) {
                               if (error != NULL) {
                                 errno = nw_error_get_error_code(error);
                                 NWLOG("write close error");
                               }
                             });
        } else {
          nw_protocol_metadata_t metadata =
              nw_ws_create_metadata(nw_ws_opcode_text);
          nw_content_context_t context = nw_content_context_create("send");
          nw_content_context_set_metadata_for_protocol(context, metadata);
          nw_connection_send(connection, read_data, context, true,
                             ^(nw_error_t _Nullable error) {
                               if (error != NULL) {
                                 errno = nw_error_get_error_code(error);
                                 NWLOG("send error");
                                 nw_release(context);
                               } else {
                                 // Continue reading from stdin
                                 send_loop(connection);
                               }
                             });
        }
      });
}
void receive_loop(nw_connection_t connection) {
  nw_connection_receive(
      connection, 1, UINT32_MAX,
      ^(dispatch_data_t content, nw_content_context_t context, bool is_complete,
        nw_error_t receive_error) {
        nw_retain(context);
        dispatch_block_t schedule_next_receive = ^{
          // If the context is marked as complete, and is the final context,
          // we're read-closed.
          if (is_complete &&
              (context == NULL || nw_content_context_get_is_final(context))) {
            exit(0);
          }

          // If there was no error in receiving, request more data
          if (receive_error == NULL) {
            receive_loop(connection);
          }
          nw_release(context);
        };

        if (content != NULL) {
          // If there is content, write it to stdout asynchronously
          schedule_next_receive = Block_copy(schedule_next_receive);
          dispatch_write(
              STDOUT_FILENO, content, dispatch_get_main_queue(),
              ^(__unused dispatch_data_t _Nullable data, int stdout_error) {
                if (stdout_error != 0) {
                  errno = stdout_error;
                  NWLOG("stdout write error");
                } else {
                  schedule_next_receive();
                }
                Block_release(schedule_next_receive);
              });
        } else {
          // Content was NULL, so directly schedule the next receive
          schedule_next_receive();
        }
      });
}
void start_send_receive_loop(nw_connection_t connection) {
  // Start reading from stdin
  send_loop(connection);

  // Start reading from connection
  receive_loop(connection);
}
