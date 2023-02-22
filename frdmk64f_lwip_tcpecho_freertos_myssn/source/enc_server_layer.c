/*
 * server_layer.c
 *
 *  Created on: Feb 15, 2023
 *      Author: doria
 */
#include "lwip/opt.h"
//#include "tcpecho.h"
#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/api.h"
#include "enc_server_layer.h"



uint8_t test_string[] = { "01234567890123456789" };
/* AES data */
uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
uint8_t iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
struct AES_ctx ctx;
size_t  padded_len;
uint8_t padded_msg[512] = { 0 };



/*************** Get socket function *******************
*
*
************************************************/
struct netconn * get_socket() {
    struct netconn * conn;

    // Create a new connection identifier.
    conn = netconn_new(NETCONN_TCP);
    PRINTF("NEW CONNECTION \r\n");

    return conn;
}

/*************** Server mode *******************
*
*
************************************************/
struct netconn * server_mode(struct netconn* socket) {
    struct netconn * newconn;
    err_t err;
    // Bind connection to well known port number 7.
    netconn_bind(socket, IP_ADDR_ANY, SOCKET_PORT_SERVER);
    PRINTF("BIND DONE\r\n");
    LWIP_ERROR("tcpecho: invalid conn", (socket != NULL), return 0;);
    // Tell connection to go into listening mode.
    PRINTF("ENTERED LISTENING \n\r");
    netconn_listen(socket);
    // Grab new connection.
    err = netconn_accept(socket, &newconn);
    PRINTF("--- SERVER MODE ---\n\r");
    PRINTF("ACCEPTED NEW CONNECTION newconn= %p\n\r", newconn);
    // Process the new connection.
    if (err == ERR_OK) {
        PRINTF("READY TO SEND/RECEIVE\n\r");
        return newconn;
    }
    else {
        PRINTF("ACCEPT FAILED\n\r");
    }
    return 0;
}
/*************** Client mode *******************
*
*
************************************************/
struct netconn * client_mode(struct netconn* socket, ip_addr_t netif_ipaddr_client) {
    err_t err;

    // Grab new connection.
    //socket, addr the remote IP address to connect to, remote port to connect t
    err = netconn_connect(socket,&netif_ipaddr_client, SOCKET_PORT_CLIENT );
    PRINTF("--- CLIENT MODE ---\n\r");
    PRINTF("CONNETED = %p\n\r", socket);
    // Process the new connection.
    if (err == ERR_OK) {
        PRINTF("READY TO SEND/RECEIVE\n\r");
        return socket;
    }
    else {
        PRINTF("CONNECTION FAILED\n\r");
    }
    return 0;
}

/*************** Close Socket *******************
*
*
************************************************/
void close_connection(struct netconn * newconn) {
    netconn_close(newconn);
    netconn_delete(newconn);
}

/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
static void InitCrc32(CRC_Type * base, uint32_t seed)
{
    crc_config_t config;

    config.polynomial = 0x04C11DB7U;
    config.seed = seed;
    config.reflectIn = true;
    config.reflectOut = true;
    config.complementChecksum = true;
    config.crcBits = kCrcBits32;
    config.crcResult = kCrcFinalChecksum;

    CRC_Init(base, &config);
}

/*************** AES Encription fnc *************
*
*
***********************************************/
aes_msg  encrypt(uint8_t message[]) {
    
    //size_t msg_string_len;
	aes_msg enc_msg;
    enc_msg.padded_msg = padded_msg;
    enc_msg.padded_len = strlen(message);
    PRINTF("LENGHT OF MESSAGE TO BE ENCRYPTED: %d", enc_msg.padded_len);

    // Init the AES context structure
    AES_init_ctx_iv(&ctx, key, iv);
    // To encrypt an array its length must be a multiple of 16 so we add zeros
    enc_msg.padded_len = enc_msg.padded_len + (16 - (enc_msg.padded_len % 16));
    
    memcpy(enc_msg.padded_msg, message, enc_msg.padded_len);
    PRINTF("\r\nMSG TO BE ENCRYPTED: ");
        	for (int i = 0; i < enc_msg.padded_len; i++) {
        	   PRINTF("%c", enc_msg.padded_msg[i]);
        	}
        	PRINTF(" \n\r");

    AES_CBC_encrypt_buffer(&ctx, enc_msg.padded_msg, enc_msg.padded_len);

    PRINTF("ENCRYPTED MESSAGE: ");
    for (int i = 0; i < enc_msg.padded_len; i++) {
        PRINTF("0x%02x,", enc_msg.padded_msg[i]);
    }
    PRINTF("\r\n");

    return enc_msg;
}


/*************** AES Decription fnc *************
*
*
************************************************/
aes_msg decrypt(uint8_t message[]) {

    aes_msg dec_msg;
    // Init the message structure
    dec_msg.padded_len =  strlen(message);
    //PRINTF("MESSAGE LENGTH TO DECRYPT: %d\r\n", dec_msg.padded_len);
    dec_msg.padded_msg = padded_msg;

    // Init the AES context structure
    AES_init_ctx_iv(&ctx, key, iv);
    
    //memcpy( *dest, src, size_t n)
    memcpy(dec_msg.padded_msg, message, dec_msg.padded_len);

    //Decrypt the buffer
    AES_CBC_decrypt_buffer(&ctx, dec_msg.padded_msg, dec_msg.padded_len);

    dec_msg.padded_len = strlen(dec_msg.padded_msg);
    PRINTF("DECRYPTED MSG: ");
    for (int i = 0; i < dec_msg.padded_len; i++) {
        //PRINTF("0x%02x,", dec_msg.padded_msg[i]);
        PRINTF("%c", dec_msg.padded_msg[i]);
    }
    PRINTF("       MSG BYTES: ");


    return dec_msg;
}

/*************** CRC calculation fnc *************
*
*
************************************************/
uint32_t calculate_crc(uint8_t message[]) {
    // CRC data
    CRC_Type* base = CRC0;
    uint32_t checksum32;
    size_t len;

    len = strlen(message);

    InitCrc32(base, 0xFFFFFFFFU);
    CRC_WriteData(base, (uint8_t*)&message[0], len);
    checksum32 = CRC_Get32bitResult(base);

    PRINTF("CALCULATED CRC-32: 0x%08x      ", checksum32);
    return checksum32;
}


/*************** Gets body and CRC of message fnc *************
*
*
************************************************/
msg_parts get_msg_components(aes_msg message) {

    msg_parts msg;
    //uint8_t padded_msg2[512] = { 0 };
    msg.body = padded_msg;
    //PRINTF("length at get_msg fnc: %d\n\r", message.padded_len);
    // Get the body and remove extra zeros
   for( int i = 0; i < message.padded_len; i++){
	   //PRINTF("0x%02x ",message.padded_msg[i] );
	   if(message.padded_msg[i] == 0){
		   message.padded_len = i;
		   break;
	   }
   }
   //Getting the body only
   PRINTF("RECEIVED MESSAGE BODY: ");
   for( int i = 0; i < message.padded_len-4; i++){
	   msg.body[i] = message.padded_msg[i];
   	   PRINTF("0x%02x ",msg.body[i] );
   }
   PRINTF("\n\r");

    msg.len = message.padded_len-4;
    // Get the CRC and make it an int

	msg.crc = (message.padded_msg[message.padded_len - 1] << 24)|
			(message.padded_msg[message.padded_len - 2] << 16) 	|
			(message.padded_msg[message.padded_len - 3] << 8) 	|
			(message.padded_msg[message.padded_len - 4]);

       PRINTF("RECEIVED MESSAGE CRC-32: 0x%08x \n\r", msg.crc );
   return msg;
}


/*************** Receive data *******************
*
*
************************************************/
void receive(struct netconn * newconn) {
    struct netbuf* buf;
    void* data;
    u16_t len;
    msg_parts msg_components;
    aes_msg recv_msg;
    uint32_t  calc_crc = 0;
    err_t err;
    PRINTF("\n\r----------- RECEIVING ----------\n\r");


    // Receive message - This function blocks the process while waiting
    //                     for data to arrive on the connection newconn
    if ( (err = netconn_recv(newconn, &buf)) == ERR_OK)
    {
        do {
            // obtain a pointer to the data in the fragment
            netbuf_data(buf, &data, &len);
        } while (netbuf_next(buf) >= 0);
        recv_msg.padded_msg = data;
        recv_msg.padded_len = len;

        // Get the CRC and body of the message
        msg_components = get_msg_components(recv_msg);

        // Calculate CRC from body
        calc_crc = calculate_crc(msg_components.body);
        // Compare CRCs
        if (calc_crc == msg_components.crc) {
            PRINTF("\n\rCRC MATCHES!, DECRYPTING.. \r\n");
            // Decrypt
            recv_msg = decrypt(msg_components.body);
            // Print results 
            for (int i = 0; i < recv_msg.padded_len; i++){
                PRINTF("0x%02x,", recv_msg.padded_msg[i]);
            }
            PRINTF("\n\r");
        }
        else {
            PRINTF("CRC DO NOT MATCH \n\r");
        }
        // Clear buffer
        netbuf_delete(buf);
        for (int i = 0; i < 512; i++){
        	padded_msg[i] = 0;
        }

        PRINTF("----------- END RECEIVE ----------\n\r");
    }
}




/***************** Send data ********************
*
*
************************************************/
void send(struct netconn * newconn, uint8_t * message) {

    uint32_t crc_msg_send;
    uint8_t crc_msk[4];
    aes_msg  enc_msg_send;
    void *data_client;
    
    PRINTF("\n\r----------- SENDING ----------\n\r");

    // Encrypt message
    enc_msg_send = encrypt(message);

    // calculate CRC
	crc_msg_send = calculate_crc(enc_msg_send.padded_msg);

    // Make CRC into 4 byte (little endian)
    //https://stackoverflow.com/questions/6499183/converting-a-uint32-value-into-a-uint8-array4
    crc_msk[0] = crc_msg_send & 0xFF;
    crc_msk[1] = crc_msg_send >> 8 & 0xFF;
    crc_msk[2] = crc_msg_send >> 16 & 0xFF;
    crc_msk[3] = crc_msg_send >> 24 & 0xFF;
    PRINTF("CRC BYTES:  :");
    for(int i = 0; i <4 ; i++){
    	PRINTF("0x%02x ",crc_msk[i] );
    }
    PRINTF("\n\r");
    // create full message encrypted + CRC
   // PRINTF("msg len before crc: %d", enc_msg_send.len);
    for (int i = 0; i < 4; i++) {
    	enc_msg_send.padded_msg[enc_msg_send.padded_len + i] = crc_msk[i];
    }


    // Update message length
    enc_msg_send.padded_len = strlen(enc_msg_send.padded_msg);
    //PRINTF("len with sterlen %d \n\r", len);
    PRINTF("LENGHT OF MESSAGE TO BE SEND WITH CRC: %d \n\r", enc_msg_send.padded_len);

    PRINTF("FULL MESSAGE TO BE SEND: ");
    for(int i=0; i < enc_msg_send.padded_len ; i++){
    	PRINTF("0x%02x ",enc_msg_send.padded_msg[i]);
    }
    PRINTF("\n\r");

    data_client = (void*) enc_msg_send.padded_msg;

    // Send message
    netconn_write(newconn, data_client, enc_msg_send.padded_len, NETCONN_COPY);
    for (int i = 0; i < 512; i++){
		padded_msg[i] = 0;
	}
    PRINTF("----------- END SENT ----------\n\r");
}







