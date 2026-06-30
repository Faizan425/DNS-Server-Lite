#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include<stdbool.h>
#include<arpa/inet.h>


struct __attribute__((packed))  DNS_Header{
	uint16_t ID;
	uint16_t flags;
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t NSCOUNT;
	uint16_t ARCOUNT;
};
struct __attribute__((packed))  DNS_Answer{
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t length;
	uint32_t data;
};

struct DNS_Message {
	struct DNS_Header* dns_header; 
};

int count;
char* read_head;
char* cursor_to_question_section;
bool forwarding;
uint16_t resolver_port;
struct sockaddr_in resolver_addr;
int udpSocket;
int resolver_socket;

char* construct_header(char* cursor, char* buffer){
//     dns_message -> dns_header = (struct DNS_Header *) calloc(1,sizeof(struct DNS_Header));
// 	dns_message -> dns_header -> flags = htons(1 << 15); // setting only the final bit 
// 	dns_message -> dns_header -> ID = htons(1234);
// 	dns_message ->dns_header ->QDCOUNT = htons(1);
    struct DNS_Header dns_header = {0};
    memcpy(&dns_header.ID, buffer, 2); // copy the id 
    memcpy(&dns_header.flags, buffer+2, 2);
    dns_header.flags = ntohs(dns_header.flags);
    dns_header.flags |= ((1<<15)); //Set the response bit
    dns_header.flags &=  (~(1<<10)); // Set AA to 0
    dns_header.flags &= (~(1<<9)); // set TC to 0
    dns_header.flags &= (~(1<<7)); // set RA to 0
    dns_header.flags &= (~((1<<6) | (1<<5) | (1<<4)));
    uint16_t flag = dns_header.flags;
    flag &= ((1<<14) | (1<<13) | (1<<12) | (1<<11)); // isolate opcode field
    flag ^= ((1<<14) | (1<<13) | (1<<12) | (1<<11)); // xor it
    uint8_t opcode = (dns_header.flags >>11) & 0x0F; 
    if(opcode == 0){ // check if OPCODE is not  set
	    dns_header.flags &= ~0x000F; //(~((1<<3) | (1<<2) | (1<<1) | 1)); // set RCODE to 0
    } else{
	    dns_header.flags &= ~0x000F;   //(~((1<<3) | (1<<2) | (1<<1) | 1)); // set all to 0
	    dns_header.flags |= 4; // set to 4
    }
    dns_header.flags = htons(dns_header.flags); 
    //dns_header.flags = htons(1 << 15);
    //dns_header.ID = htons(1234);
    //dns_header.QDCOUNT = htons(1);
    memcpy(&dns_header.QDCOUNT, buffer + 4, 2);

    count = ntohs(dns_header.QDCOUNT);

    dns_header.ANCOUNT = dns_header.QDCOUNT;
    // 3. Copy it directly to the buffer
    memcpy(cursor, &dns_header, sizeof(struct DNS_Header));
    
    // 4. Return the advanced cursor
    return cursor + sizeof(struct DNS_Header);
}

char*  construct_question(char* cursor, char* buffer){
	if(read_head == NULL){
		read_head = buffer + sizeof(struct DNS_Header);
	}
	size_t question_length = 0;
	//uint16_t pointer = (*read_head &((1<<15) | (1<<14)) );
	if((*read_head & 0xC0) == 0xC0){ //check if pointer is set
		//uint16_t offset = *read_head & 0x3fff;
		//Mask the first byte with 0x3F, Shift it left by 8 and OR it with second byte
		uint16_t offset = ((read_head[0] & 0x3F) <<8) | (uint8_t)read_head[1];
		char* tmp = read_head;
		read_head = buffer + (size_t)offset;
		while(*(read_head + question_length) != '\0'){
			question_length+=1;
		}
		question_length +=1;
		memcpy(cursor, read_head, question_length);
		read_head = tmp + 2; //move past the pointer and offset
		memcpy(cursor + question_length, read_head , 2); // get the QTYPE
		memcpy(cursor + question_length + 2, read_head + 2,2); // get the QCLASS
		read_head  +=  4;
		return cursor + question_length + 4;
	} else {
	while(*(read_head + question_length) != '\0'){
		question_length+=1;
	}
	question_length+=1; // include the null byte
	memcpy(cursor , read_head , question_length);
	memcpy(cursor + question_length, read_head + question_length, 2); // copy the Type
	memcpy(cursor + question_length + 2, read_head + question_length + 2,2); // copy the Class
        read_head += question_length+4;
	//question_length +=4; // include Type and class
	//question_length -= sizeof(struct DNS_Header);
	//memcpy(cursor, buffer + sizeof(struct DNS_Header), question_length);
	return cursor + question_length + 4;
	//cursor += question_length;
	}
}

char* construct_answer(char* cursor){
	size_t name_length = 0;
	//cur + 12 + name_length;
	while(*(cursor_to_question_section + name_length) != '\0'){
		name_length++;
	}
	name_length+=1; // include the null byte
	memcpy(cursor, cursor_to_question_section , name_length); //cur + 12
	cursor+=name_length;

	struct DNS_Answer dns_answer = {0};
	dns_answer.type = htons(1);
	dns_answer.class = htons(1);
	dns_answer.ttl = htonl(60);
	dns_answer.length = htons(4);
	dns_answer.data = htonl(0x08080808);
	
	memcpy(cursor, &dns_answer, sizeof(struct DNS_Answer));
	//memcpy(cursor, buffer+ sizeof(struct DNS_Header)+ question_length , counter);
	cursor += sizeof(struct DNS_Answer);
	cursor_to_question_section += name_length + 4;
	return cursor;

}

int construct_response(char* dns_response, char* buffer, char* cursor){
// 	dns_message = calloc(1, sizeof(struct DNS_Message));
        read_head = NULL;
	cursor = dns_response;
	char* cursor_to_header = cursor;
	cursor = construct_header(cursor, buffer);
	cursor_to_question_section = cursor;
	int tmp = count;
	char sub_dns_query[512];
	while(count != 0){
		/*
		if(forwarding){

			if(sendto(udpSocket, dns_response, response_length, 0, (struct sockaddr*)&resolver_addr, sizeof(resolver_addr)) == -1) {
				perror("Failed to send response");
			}
		}*/
		cursor =  construct_question(cursor, buffer);
		count -= 1;
	}
	count = tmp;
	struct DNS_Header* header;
	char answer_buffer[512];
	int name_length = 0;
	socklen_t resolver_addr_len = sizeof(resolver_addr);
	while(count != 0){
		if(forwarding){
			header = (struct DNS_Header*) cursor_to_header;
			header->QDCOUNT = htons(1);
			header ->ANCOUNT = htons(0);
			header -> flags = ntohs(header -> flags);
			header ->flags &= (~(1<<15)); // set the query bit
		        header -> flags = htons(header -> flags);
			memset(sub_dns_query, 0, sizeof(sub_dns_query));
		        memcpy(sub_dns_query, header, sizeof( struct DNS_Header));
	                name_length = 0;
			memset(answer_buffer, 0, sizeof(answer_buffer));
	                while(*(cursor_to_question_section + name_length) != '\0'){
				name_length+=1;
			}
	                name_length+=1; // null byte
			memcpy(sub_dns_query + sizeof(struct DNS_Header), cursor_to_question_section, name_length+4);
	                		
			if(sendto(resolver_socket, sub_dns_query, sizeof(struct DNS_Header) + name_length + 4, 0 ,(struct sockaddr *)&resolver_addr, (socklen_t) sizeof(resolver_addr)) == -1){
				perror("Failed to send Query");
			}
			cursor_to_question_section+= name_length + 4;
			int bytesRead = recvfrom(resolver_socket, answer_buffer, sizeof(answer_buffer), 0, (struct sockaddr*)&resolver_addr, (socklen_t *)&resolver_addr_len);
			memcpy(cursor, answer_buffer+12+name_length + 4, bytesRead-(12 + name_length + 4));
			if(bytesRead == -1){
				perror("Failed to retrieve response");
			}
			cursor += (bytesRead - (12 + name_length + 4));
			header ->QDCOUNT = htons(tmp);
			header ->ANCOUNT = htons(tmp);
			header -> flags = ntohs(header -> flags);
			header ->flags |= ((1<<15)); // reset to their previous values
			header -> flags = htons(header -> flags); // reset to their previous values
			/*if(count == 1){
				close(resolver_socket); // close the temp socket if it is the last iteration
			}*/

		}
		else{
		cursor = construct_answer(cursor);
		}
		count -=1;
	}
	return cursor - dns_response;

}

int main(int argc, char* argv[]) {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);
	forwarding = false;
	char* resolver_info = NULL;
	char resolver_ip[16];
	memset(&resolver_addr, 0, sizeof(resolver_addr));
	resolver_addr.sin_family = AF_INET;
	for(int i = 1; i < argc-1; i++){
		if(strcmp(argv[i],"--resolver") == 0){
			forwarding = true;
			resolver_socket = socket(AF_INET, SOCK_DGRAM, 0);
			resolver_info = strtok(argv[i+1], ":");
			//memcpy(resolver_ip, resolver_info, 16);
			if(inet_pton(AF_INET, resolver_info,&resolver_addr.sin_addr) <=0){
				perror("Invalid IP Address or format");
				exit(EXIT_FAILURE);
			}
			resolver_info = strtok(NULL, ":");
			resolver_port = atoi(resolver_info);
			//memcpy(&resolver_port, resolver_info, 2);
			resolver_addr.sin_port = htons(resolver_port);

		}
	}
	/*
	memset(&resolver_addr, 0 ,sizeof(resolver_addr));
	resolver_addr.sin_family = AF_INET;
	resolver_addr.sin_port = htons(resolver_port);
	if(inet_pton(AF_INET, resolver_ip, &resolver_addr.sin_addr) <= 0){
		perror("Invalid IP Address or format");
		exit(EXIT_FAILURE);
	}*/

	// You can use print statements as follows for debugging, they'll be visible when running tests.
    printf("Logs from your program will appear here!\n");

    // TODO: Uncomment the code below to pass the first stage
        //udpSocket; //, client_addr_len;
	struct sockaddr_in clientAddress;
	
	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpSocket == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	
	// Since the tester restarts your program quite often, setting REUSE_PORT
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEPORT failed: %s \n", strerror(errno));
		return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
					.sin_port = htons(2053),
					.sin_addr = { htonl(INADDR_ANY) },
					};
	
	if (bind(udpSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

    int bytesRead;
    char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);
    
    while (1) {
        // Receive data
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientAddrLen);
	if (bytesRead == -1) {
            perror("Error receiving data");
            break;
        }
	char dns_response[512];
	char* cursor;
	cursor = dns_response;
// 	struct DNS_Message* dns_message = NULL;
	int response_length= construct_response(dns_response, buffer, cursor);
        //buffer[bytesRead] = '\0';
        //printf("Received %d bytes: %s\n", bytesRead, buffer);
    
        // Create an empty response
        //char response[1] = { '\0' };
    
        // Send response
        if (sendto(udpSocket, dns_response, response_length, 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) == -1) {
            perror("Failed to send response");
        }
// 	free(dns_message->dns_header);
// 	free(dns_message);
    }
    
    close(udpSocket);

    return 0;
}


