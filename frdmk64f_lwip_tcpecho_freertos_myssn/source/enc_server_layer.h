
#include "fsl_debug_console.h"
#include "aes.h"
#include "fsl_crc.h"
#include "lwip/api.h"

#define SOCKET_PORT_CLIENT 7
#define SOCKET_PORT_SERVER 7
/*This structure is used for the aes encription it contains its message and the lengh*/
typedef struct aes_msg {
	uint8_t* padded_msg;
	size_t padded_len;
}aes_msg;

/*This structure is used for the received messages components*/
typedef struct msg_parts {
	uint8_t* body;
	size_t len;
	uint32_t crc;
}msg_parts;


/*Function prototypes*/
static void InitCrc32(CRC_Type* base, uint32_t seed);
aes_msg encrypt(uint8_t message[]);
aes_msg decrypt(uint8_t message[]);
uint32_t calculate_crc(uint8_t message[]);
msg_parts get_msg_components(aes_msg message);
struct netconn* get_socket();
struct netconn* server_mode(struct netconn* socket);
struct netconn * client_mode(struct netconn* socket, ip_addr_t netif_ipaddr_client);
void receive(struct netconn* newconn);
void send(struct netconn* newconn, uint8_t *);
void close_connection(struct netconn* newconn);

