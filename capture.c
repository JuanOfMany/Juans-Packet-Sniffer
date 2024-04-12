#include <stdio.h>
#include <string.h>
#include <time.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>

#define MAX_NUMBER_STRINGS 7
#define MAX_STRING_SIZE 64
#define DEVICE_NAME "en0"
#define MAX_BYTES 1600
#define MAX_PACKETS 5
#define ETHERNET_ADDR_LEN 6
#define ETHERNET_SIZE 14
#define IP_HEADER_LEN(ip) ((ip->ip_ver_header_len) & 0x0f)
#define IP_VER(ip) ((ip->ip_ver_header_len) >> 4)

struct tm *time_sniffed;
char tmbuf[64], buf[24];
int current_packet = 0;

struct ethernet_sniffer
{
    u_char ether_dest_host[ETHERNET_ADDR_LEN];
    u_char ether_src_host[ETHERNET_ADDR_LEN];
    u_short ether_type;
};

struct ip_sniffer
{
 #define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char ip_ver_header_len;
    u_char ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_time_to_live;
    u_char ip_protocol;
    u_short ip_checksum;
    u_int ip_ver;
    char * time_sniffed;
    struct in_addr ip_src_addr, ip_dest_addr;
};

struct ip_sniffer packets[MAX_PACKETS];

const struct ethernet_sniffer *ethernet;
struct ip_sniffer *ip;
const u_char *payload;

u_int ip_header_len;
u_int ip_ver;

void load_css(void)
{
    GtkCssProvider *provider;
    GdkDisplay *display;
    GdkScreen *screen;

    const gchar *css_file = "style.css";
    GFile *css_fp = g_file_new_for_path(css_file);
    GError *error = 0;

    provider = gtk_css_provider_new();
    display = gdk_display_get_default();
    screen = gdk_display_get_default_screen(display);

    gtk_style_context_add_provider_for_screen(screen, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_css_provider_load_from_file(provider, css_fp, &error);

    if (!gtk_css_provider_load_from_file(provider, css_fp, &error))
    {
        g_printerr("Error loading CSS: %s\n", error->message);
        g_clear_error(&error);
    }

    g_object_unref(provider);
}

static void activate(GtkApplication *app, gpointer user_data)
{
    GtkWidget *window;
    GtkWidget *button;
    GtkWidget *grid;

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Juan's Packet Sniffer");

    grid = gtk_grid_new();

    load_css();

    gtk_window_set_default_size(GTK_WINDOW(window), 500, 500);

    int i;
    char str[64];
    int row = 2;
    int column = 1;

    char packet_data[MAX_NUMBER_STRINGS][MAX_STRING_SIZE];
    strcpy(packet_data[0], "Packet Id");
    strcpy(packet_data[1], "Time Sniffed");
    strcpy(packet_data[2], "IP Version");
    strcpy(packet_data[3], "Source IP");
    strcpy(packet_data[4], "Desitination IP");
    strcpy(packet_data[5], "Checksum");
    strcpy(packet_data[6], "Time to Live");

    int index;

    for (index = 0; index < MAX_NUMBER_STRINGS; index++)
    {
        GtkWidget *title_frame = gtk_frame_new(packet_data[index]);
        gtk_frame_set_shadow_type(GTK_FRAME(title_frame), GTK_SHADOW_NONE);
        gtk_grid_attach(GTK_GRID(grid), title_frame, index + 1, 1, 1, 1);
    }

    // populate rows with packet data
    // for every packet
    for (i = 0; i < MAX_PACKETS; i++)
    {
        // for all packet details
        for (int j = 0; j < MAX_NUMBER_STRINGS; j++)
        {
            // create a frame and add packet detail
            GtkWidget *frame;
            switch (j)
            {
            case 0:
                sprintf(str, "%d", packets[i].ip_id);
                break;
            case 1:
                sprintf(str, "%s", packets[i].time_sniffed);
                break;
            case 2:
                sprintf(str, "%u", (packets[i].ip_ver));
                break;
            case 3:
                sprintf(str, "%s", inet_ntoa(packets[i].ip_src_addr));
                break;
            case 4:
                sprintf(str, "%s", inet_ntoa(packets[i].ip_dest_addr));
                break;
            case 5:
                sprintf(str, "%u", packets[i].ip_checksum);
                break;
            case 6:
                sprintf(str, "%u", packets[i].ip_time_to_live);
                break;
            default:
                break;
            }
            frame = gtk_frame_new(str);
            gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_NONE);
            gtk_grid_attach(GTK_GRID(grid), frame, column, row, 1, 1);
            column++;
        }
        column = 1;
        row++;
    }
    gtk_container_add(GTK_CONTAINER(window), grid);

    gtk_widget_show_all(window);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ethernet = (struct ethernet_sniffer *)(packet);
    ip = (struct ip_sniffer *)(packet + ETHERNET_SIZE);
    ip_header_len = IP_HEADER_LEN(ip) * 4;
    ip_ver = IP_VER(ip);

    if (ip_header_len < 20)
    {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", ip_header_len);
        return;
    }

    payload = (u_char *)(packet + ETHERNET_SIZE + ip_header_len);

    u_int payload_length = header->len - ip_header_len;

    time_sniffed = localtime(&header->ts.tv_sec);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S %Z", time_sniffed);
    snprintf(buf, sizeof buf, "%s.%ld", tmbuf, header->ts.tv_sec);

    // printf("Payload length is: %i.\n", payload_length);
    // printf("Found an IP packet with a header length: %u bytes\n", ip_header_len);
    // printf("And a total length of: %u bytes\n", (header->len));
    // printf("With a IP version of: %u\n", ip_ver);
    // printf("And a checksum value of: %u\n", ip->ip_checksum);
    // printf("Source IP: %s\n", inet_ntoa(ip->ip_src_addr));
    // printf("Destination IP: %s\n", inet_ntoa(ip->ip_dest_addr));
    // printf("With a time to live of: %u\n", ip->ip_time_to_live);
    // printf("And a protocol of: %u\n", ip->ip_protocol);
    // printf("At time: %s\n", buf);
    // printf("And a payload of:\n");
    // for (int i = 0; i < payload_length; i++)
    // {
    //     printf("%u", payload[i]);
    // };
    // printf("\n");

    ip->time_sniffed = strdup(buf);
    ip->ip_ver = ip_ver;
    packets[current_packet] = *ip;
    current_packet++;
};

int main(int argc, char **argv)
{
    GtkApplication *app;
    int status;

    app = gtk_application_new("org.gtk.example", G_APPLICATION_DEFAULT_FLAGS);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    pcap_if_t *all_devices;
    char *device;

    if (pcap_findalldevs(&all_devices, errbuf) == 0)
    {
        while (all_devices)
        {
            if (strcmp(all_devices->name, DEVICE_NAME) == 0)
            {
                handle = pcap_open_live(all_devices->name, MAX_BYTES, 1, 1000, errbuf);
                if (handle == NULL)
                {
                    fprintf(stderr, "Couldn't open device %s: %s\n", all_devices->name, errbuf);
                    return (2);
                }
                if (pcap_datalink(handle) != DLT_EN10MB)
                {
                    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", all_devices->name);
                    return (2);
                }

                pcap_loop(handle, MAX_PACKETS, packet_handler, NULL);

                pcap_close(handle);
            }

            all_devices = all_devices->next;
        }
        pcap_freealldevs(all_devices);
    }
    else
    {
        fprintf(stderr, "Device not found: %s\n", errbuf);
        return 1;
    }

    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    
    status = g_application_run(G_APPLICATION(app), argc, argv);

    g_object_unref(app);
    return status;
}

// used Github Copilot for unblocking, debugging, and learning.
// must use sudo to run executable or otherwise admin level access.

// compile command:
// gcc `pkg-config --cflags --libs gtk+-3.0` capture.c -lpcap

// older compile command:
// cc `pkg-config --cflags gtk+-3.0` capture.c -o capture `pkg-config --libs gtk+-3.0`

// bash command to direct pkg_config to homebrew installed library .pc files
// export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:/opt/homebrew/opt/libffi/lib/pkgconfig:/opt/homebrew/opt/zlib/lib/pkgconfig:/opt/homebrew/opt/expat/lib/pkgconfig"
