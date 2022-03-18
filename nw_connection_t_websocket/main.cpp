/*
 Start a websocket link to input address, program will open a small chat room endpoint to endpoint.
 This demo is 
 */

#include "Network/Network.h"
#include <string>
#include <err.h>

char* g_psk = nullptr;//TLS_PSK. For general websocket link, rsk is not used
char* g_local_port = nullptr;// Local port, use as inbound endpoint
char* g_local_address = nullptr;
bool g_use_bonjour = false;
bool g_listener = false;
bool g_use_udp = false;
bool g_use_tls = false;
bool g_verbose = true;
int g_family = AF_UNSPEC;



nw_connection_t create_ws_connection(const char* address, const char* port){
    std::string sock_host_address = "ws://127.0.0.1:8080";
    g_family = AF_INET;
//    sockaddr addr;
//    addr.sa_family = g_family;
//    addr.sa_data = sockAddress.c_str();
//    addr.sa_len = sizeof(sockaddr);
    
    //TODO: which is correct? create url or create host?
//    nw_endpoint_t endpoint = nw_endpoint_create_host(address, port);
    nw_endpoint_t endpoint = nw_endpoint_create_url(sock_host_address.c_str());
    nw_endpoint_type_t endpoint_type = nw_endpoint_get_type(endpoint);
    printf("endpoint type is %d \n", endpoint_type);
    //const struct sockaddr * address = nw_endpoint_get_address(endpoint);
    
    nw_parameters_configure_protocol_block_t configure_tls;
    if(g_use_tls){
        if(g_psk){
            //TODO: handle link with tls
        }
    }
    else{
        //without tls, it becomes default configuration
        configure_tls = NW_PARAMETERS_DEFAULT_CONFIGURATION;
    }
    configure_tls = NW_PARAMETERS_DISABLE_PROTOCOL;
//    configure_tls = NW_PARAMETERS_DEFAULT_CONFIGURATION;
    
    nw_parameters_t parameters;
    if(g_use_udp){
        parameters = nw_parameters_create_secure_udp(configure_tls,
                                                     NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }else{
        parameters = nw_parameters_create_secure_tcp(configure_tls,
                                                     NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }
    nw_protocol_stack_t protocol_stack = nw_parameters_copy_default_protocol_stack(parameters);
    if(g_family == AF_INET || g_family == AF_INET6){
        //TODO: copy transport protocol or internet protocol?
//        nw_protocol_options_t websocket_options = nw_protocol_stack_copy_transport_protocol(protocol_stack);
        nw_protocol_options_t websocket_options = nw_ws_create_options(nw_ws_version_13);
//        nw_ip_options_set_version(websocket_options, nw_ip_version_4);
        nw_protocol_stack_prepend_application_protocol(protocol_stack, websocket_options);
        
    }
//    nw_protocol_definition_t websocket_default_definition = nw_protocol_copy_ws_definition();
    nw_parameters_set_local_endpoint(parameters, endpoint);
    nw_release(protocol_stack);
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    nw_release(endpoint);
    nw_release(parameters);
    return connection;
}
void start_connection(nw_connection_t connection){
    nw_connection_set_queue(connection, dispatch_get_main_queue());

    nw_retain(connection); // Hold a reference until cancelled
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        nw_endpoint_t remote = nw_connection_copy_endpoint(connection);
        errno = error ? nw_error_get_error_code(error) : 0;
        if (state == nw_connection_state_waiting) {
            warn("connect to %s port %u (%s) failed, is waiting",
                 nw_endpoint_get_hostname(remote),
                 nw_endpoint_get_port(remote),
                 g_use_udp ? "udp" : "tcp");
        } else if (state == nw_connection_state_failed) {
            warn("connect to %s port %u (%s) failed",
                 nw_endpoint_get_hostname(remote),
                 nw_endpoint_get_port(remote),
                 g_use_udp ? "udp" : "tcp");
        } else if (state == nw_connection_state_ready) {
            if (g_verbose) {
                fprintf(stderr, "Connection to %s port %u (%s) succeeded!\n",
                        nw_endpoint_get_hostname(remote),
                        nw_endpoint_get_port(remote),
                        g_use_udp ? "udp" : "tcp");
            }
        } else if (state == nw_connection_state_cancelled) {
            // Release the primary reference on the connection
            // that was taken at creation time
            nw_release(connection);
        }
        nw_release(remote);
    });
    nw_connection_start(connection);
}
void send_loop(nw_connection_t connection){
    dispatch_read(STDIN_FILENO, 8192, dispatch_get_main_queue(), ^(dispatch_data_t _Nonnull read_data, int stdin_error){
        if(stdin_error != 0){
            errno = stdin_error;
            warn("stdin read error");
        } else if (read_data == NULL) {
            nw_connection_send(connection, NULL, NW_CONNECTION_FINAL_MESSAGE_CONTEXT, true, ^(nw_error_t _Nullable error){
                if (error != NULL) {
                    errno = nw_error_get_error_code(error);
                    warn("write close error");
                }
            });
        } else {
            const char *messageC{"Hello mac"};
            dispatch_data_t content = dispatch_data_create(messageC, strlen(messageC), dispatch_get_main_queue(), DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                    
            nw_protocol_metadata_t metadata = nw_ws_create_metadata(nw_ws_opcode_text);
            nw_content_context_t context = nw_content_context_create("send");
            nw_content_context_set_metadata_for_protocol(context, metadata);
            nw_connection_send(connection, content, context, true, ^(nw_error_t  _Nullable error) {
                if (error != NULL) {
                    errno = nw_error_get_error_code(error);
                    warn("send error");
                } else {
                    // Continue reading from stdin
                    send_loop(connection);
                }
            });
        }
    });
}
void
receive_loop(nw_connection_t connection)
{
    nw_connection_receive(connection, 1, UINT32_MAX, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {

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
            dispatch_write(STDOUT_FILENO, content, dispatch_get_main_queue(), ^(__unused dispatch_data_t _Nullable data, int stdout_error) {
                if (stdout_error != 0) {
                    errno = stdout_error;
                    warn("stdout write error");
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
void
start_send_receive_loop(nw_connection_t connection)
{
    // Start reading from stdin
    send_loop(connection);

    // Start reading from connection
    receive_loop(connection);
}
int main(int argc, const char * argv[]) {
    nw_connection_t connection = create_ws_connection("127.0.0.1", "8080");
    if(connection == NULL){
        err(1, NULL);
    }
    start_connection(connection);
    warn("start connection successed\n");
    start_send_receive_loop(connection);
    dispatch_main();
    return 0;
}
