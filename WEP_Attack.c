#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include <curl/curl.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define MAX_SIZE_ARP_TABLE 2000
#define ETHERTYPE_IP 0x0800
#define SPAM_CRITIC_RIPETITION_VALUE 3
#define SIZE_DATA_CRIPTED 54

struct kickOutLoggerStruct {
    u_char mac_source[25];
    u_char mac_destination[25];
    u_int count;
};

FILE *fOut;

char *pcap_file_name = "new_input.pcap";
char *output_file_name = "error_log.txt";
int packet_counter;
int kickOutLoggerSize = 0;
struct kickOutLoggerStruct kickOutLogger[MAX_SIZE_ARP_TABLE];
int kickOutLoggerSize2 = 0;
struct kickOutLoggerStruct kickOutLogger2[MAX_SIZE_ARP_TABLE];

void intToStringIP(int ip, char *string_ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(string_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void hexStringToStingIp(const char *ipAddress, char *string_ip) {
    sprintf(string_ip, "%d.%d.%d.%d", ipAddress[0] & 0xFF, ipAddress[1] & 0xFF, ipAddress[2] & 0xFF, ipAddress[3] & 0xFF);
}

void hexStringToStringMAC(const char *macAddress, char *result) {
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x",
            macAddress[0] & 0xFF, macAddress[1] & 0xFF, macAddress[2] & 0xFF,
            macAddress[3] & 0xFF, macAddress[4] & 0xFF, macAddress[5] & 0xFF);
}

int calculateSequenceNumber(int n) {
    int sequenceNumber = 0;
    for (int i = 15; i >= 4; --i) {
        if ((n >> i) & 1) {
            sequenceNumber += (1 << (i - 4));
        }
    }
    return sequenceNumber;
}

int calculateFragmentNumber(int n) {
    return n & 0xF;
}

int kickOutSpamAnalyser(char *mac_sender, char *mac_target) {
    for (int i = 0; i < kickOutLoggerSize; i++) {
        if (strcmp(kickOutLogger[i].mac_source, mac_sender) == 0 &&
            strcmp(kickOutLogger[i].mac_destination, mac_target) == 0) {
            kickOutLogger[i].count++;
            if (kickOutLogger[i].count > SPAM_CRITIC_RIPETITION_VALUE) {
                return kickOutLogger[i].count;
            }
            return 0;
        }
    }

    strcpy(kickOutLogger[kickOutLoggerSize].mac_source, mac_sender);
    strcpy(kickOutLogger[kickOutLoggerSize].mac_destination, mac_target);
    kickOutLogger[kickOutLoggerSize].count = 1;
    kickOutLoggerSize++;
    return 0;
}

int kickOutSpamAnalyserARP(char *mac_sender, char *mac_target) {
    for (int i = 0; i < kickOutLoggerSize2; i++) {
        if (strcmp(kickOutLogger2[i].mac_source, mac_sender) == 0 &&
            strcmp(kickOutLogger2[i].mac_destination, mac_target) == 0) {
            kickOutLogger2[i].count++;
            if (kickOutLogger2[i].count > SPAM_CRITIC_RIPETITION_VALUE) {
                return kickOutLogger2[i].count;
            }
            return 0;
        }
    }

    strcpy(kickOutLogger2[kickOutLoggerSize2].mac_source, mac_sender);
    strcpy(kickOutLogger2[kickOutLoggerSize2].mac_destination, mac_target);
    kickOutLogger2[kickOutLoggerSize2].count = 1;
    kickOutLoggerSize2++;
    return 0;
}

struct radiotap_header {
    uint8_t revision;
    uint8_t pad;
    uint16_t length;
};

struct frame_control_field {
    uint8_t subtype;
    uint8_t flags;
};

struct payload {
    uint16_t duration;
    u_char destination[ETHER_ADDR_LEN];
    u_char source[ETHER_ADDR_LEN];
    u_char bssid[ETHER_ADDR_LEN];
    uint16_t data1;
};

void send_sms_alert(const char *message) {
    CURL *curl;
    CURLcode res;
    char post_data[1024];

    snprintf(post_data, sizeof(post_data),
             "To=+918438739677&From=+12562746029&Body=%s",
             message);

    curl = curl_easy_init();
    if (curl) {
        // Replace with your correct Account SID and Auth Token
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.twilio.com/2010-04-01/Accounts/AC252378654a8a9e68f05287c2f8ba40d8/Messages.json");
        curl_easy_setopt(curl, CURLOPT_USERNAME, "AC252378654a8a9e68f05287c2f8ba40d8");  // Replace with your Account SID
        curl_easy_setopt(curl, CURLOPT_PASSWORD, "9a05d0ca444b8b60c3d540c83470e48f");    // Replace with your Auth Token
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "SMS alert failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }
}


void block_mac_address(const char *mac) {
    char command[128];
    snprintf(command, sizeof(command), "sudo iptables -A INPUT -m mac --mac-source %s -j DROP", mac);
    system(command);  // Call iptables to block the MAC address
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_counter++;
    if (packet_counter > MAX_SIZE_ARP_TABLE) return;

    // Safety check for packet size
    if (header->len < sizeof(struct radiotap_header)) {
        fprintf(fOut, "Packet too small for radiotap header\n");
        return;
    }

    struct radiotap_header *radioTapHeader = (struct radiotap_header *)packet;

    if (header->len < radioTapHeader->length + sizeof(struct frame_control_field)) {
        fprintf(fOut, "Packet too small for frame control field\n");
        return;
    }

    struct frame_control_field *frameControlField = (struct frame_control_field *)(packet + radioTapHeader->length);
    int subtypeNum = (frameControlField->subtype & 0xF);

    struct payload *payloadData = (struct payload *)(packet + radioTapHeader->length + 2);
    char mac_source[25], mac_destination[25], mac_bssid[25];
    hexStringToStringMAC(payloadData->source, mac_source);
    hexStringToStringMAC(payloadData->destination, mac_destination);
    hexStringToStringMAC(payloadData->bssid, mac_bssid);
    
    // Identify the type of attack
    const char *attack_type = (subtypeNum == 12) ? "Deauthentication Attack" : "Disassociation Attack";
    
    // Print details
    fprintf(fOut, "Payload: duration:%d destination:%s source:%s bssid:%s sequence num:%d fragment num:%d\n",
           payloadData->duration, mac_destination, mac_source, mac_bssid,
           calculateSequenceNumber(payloadData->data1), calculateFragmentNumber(payloadData->data1));

    int kickSpamCounter = kickOutSpamAnalyser(mac_source, mac_destination);
    if (kickSpamCounter != 0) {
        char alert_message[256];
        snprintf(alert_message, sizeof(alert_message),
                 "Warning: %s detected! Source: %s, Destination: %s, Sequence Number: %d, Fragment Number: %d. Multiple packets found {#%d}",
                 attack_type, mac_source, mac_destination,
                 calculateSequenceNumber(payloadData->data1), calculateFragmentNumber(payloadData->data1), kickSpamCounter);
        send_sms_alert(alert_message);
        block_mac_address(mac_source);  // Block the MAC address
    }
}

int main(int argc, char **argv) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    packet_counter = 0;

    handle = pcap_open_offline(pcap_file_name, error_buffer);
    if (!handle) {
        fprintf(stderr, "Error: Unable to open the pcap file %s. Error: %s\n", pcap_file_name, error_buffer);
        return 1;
    }

    fOut = fopen(output_file_name, "a");
    if (fOut == NULL) {
        printf("Error in opening file %s\n", output_file_name);
        return 1;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);

    fclose(fOut);
    pcap_close(handle);

    return 0;
}

