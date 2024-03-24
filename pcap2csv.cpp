#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <cstdio>
#include <cstdlib>
#include <unordered_map>

std::unordered_map<uint32_t, uint32_t> map_total_pkts;
std::unordered_map<uint32_t, uint32_t> map_pkt_size_avg;
std::unordered_map<uint32_t, uint32_t> map_pkt_size_max;
std::unordered_map<uint32_t, uint32_t> map_pkt_size_min;
std::unordered_map<uint32_t, uint32_t> map_pkt_ts;
std::unordered_map<uint32_t, uint32_t> map_ipd_min;
std::unordered_map<uint32_t, uint32_t> map_pkt_size_var;
std::unordered_map<uint32_t, FILE*> map_src_csv;

int main(int argc, char **argv) {
  pcap_t *cap;
  char errbuf[PCAP_ERRBUF_SIZE];

  cap = pcap_open_offline(argv[1], errbuf);
  if (cap == nullptr) {
    fprintf(stderr, "error reading pcap file: %s\n", errbuf);
    exit(1);
  }

  FILE *csv_train = std::fopen(argv[2], "w");
  if (csv_train == nullptr) {
    fprintf(stderr, "error opening csv file: %s\n", argv[2]);
    exit(1);
  }
  FILE *csv_test = std::fopen(argv[3], "w");
  if (csv_test == nullptr) {
    fprintf(stderr, "error opening csv file: %s\n", argv[3]);
    exit(1);
  }

  std::printf("processing pcap file: %s -> (%s, %s)\n", argv[1], argv[2], argv[3]);

  // Write csv header
  std::fprintf(csv_train, "ip_src,ip_dst,total_pkts,pkt_size_avg,pkt_size_max,pkt_size_min,"
                    "pkt_size_var,ipd,ipd_min,ip_total_len,ip_ttl,ip_protocol,"
                    "ip_diffserv,tcp_window,tcp_data_offset,udp_len\n");
  std::fprintf(csv_test, "ip_src,ip_dst,total_pkts,pkt_size_avg,pkt_size_max,pkt_size_min,"
                    "pkt_size_var,ipd,ipd_min,ip_total_len,ip_ttl,ip_protocol,"
                    "ip_diffserv,tcp_window,tcp_data_offset,udp_len\n");

  struct pcap_pkthdr *pkt_hdr = new struct pcap_pkthdr;

  while (true) {
    const u_char *pkt_data = pcap_next(cap, pkt_hdr);
    if (pkt_data == nullptr)
      break;

    const struct ether_header *eth_hdr =
        reinterpret_cast<const struct ether_header *>(pkt_data);
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
      continue;

    const struct ip *ip_hdr =
        reinterpret_cast<const struct ip *>(pkt_data + sizeof(*eth_hdr));
    if (ip_hdr->ip_p != IPPROTO_TCP && ip_hdr->ip_p != IPPROTO_UDP)
      continue;

    uint32_t flow_feat = ip_hdr->ip_src.s_addr;
    if (!map_src_csv.count(flow_feat))
      map_src_csv[flow_feat] = (rand() & 1) ? csv_train : csv_test;
    FILE *csv = map_src_csv[flow_feat];

    try {
      // The flow exists
      uint32_t old_total_pkts = map_total_pkts.at(flow_feat);
      uint32_t old_pkt_size_avg = map_pkt_size_avg.at(flow_feat);
      uint32_t old_pkt_size_max = map_pkt_size_max.at(flow_feat);
      uint32_t old_pkt_size_min = map_pkt_size_min.at(flow_feat);
      uint32_t old_pkt_ts = map_pkt_ts.at(flow_feat);
      uint32_t old_ipd_min = map_ipd_min.at(flow_feat);
      uint32_t old_pkt_size_var = map_pkt_size_var.at(flow_feat);

      uint16_t ipv4_total_len = ntohs(ip_hdr->ip_len);
      uint8_t ipv4_ttl = ip_hdr->ip_ttl;
      uint8_t ipv4_protocol = ip_hdr->ip_p;
      uint8_t ipv4_tos = ip_hdr->ip_tos;

      uint32_t new_total_pkts = old_total_pkts + 1;
      uint32_t new_pkt_size_avg =
          (old_pkt_size_avg * old_total_pkts + ipv4_total_len) / new_total_pkts;
      uint32_t new_pkt_size_max =
          std::max(old_pkt_size_max, static_cast<uint32_t>(ipv4_total_len));
      uint32_t new_pkt_size_min =
          std::min(old_pkt_size_min, static_cast<uint32_t>(ipv4_total_len));
      uint32_t new_pkt_ts = pkt_hdr->ts.tv_sec * 1000000 + pkt_hdr->ts.tv_usec;
      uint32_t new_ipd = new_pkt_ts - old_pkt_ts;
      uint32_t new_ipd_min = std::min(old_ipd_min, new_ipd);
      uint32_t new_pkt_size_var = (old_pkt_size_var * old_total_pkts +
                                   ipv4_total_len * ipv4_total_len) /
                                  new_total_pkts;

      map_total_pkts[flow_feat] = new_total_pkts;
      map_pkt_size_avg[flow_feat] = new_pkt_size_avg;
      map_pkt_size_max[flow_feat] = new_pkt_size_max;
      map_pkt_size_min[flow_feat] = new_pkt_size_min;
      map_pkt_ts[flow_feat] = new_pkt_ts;
      map_ipd_min[flow_feat] = new_ipd_min;
      map_pkt_size_var[flow_feat] = new_pkt_size_var;

      uint16_t tcp_window = 0;
      uint8_t tcp_data_offset = 0;
      uint16_t udp_len = 0;

      if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp_hdr = reinterpret_cast<const struct tcphdr *>(
            pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
        tcp_window = ntohs(tcp_hdr->th_win);
        tcp_data_offset = tcp_hdr->th_off;
      } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp_hdr = reinterpret_cast<const struct udphdr *>(
            pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
        udp_len = ntohs(udp_hdr->uh_ulen);
      }

      // Write csv row
      std::fprintf(csv, "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
                   ip_hdr->ip_src.s_addr,ip_hdr->ip_dst.s_addr, new_total_pkts, new_pkt_size_avg,
                   new_pkt_size_max, new_pkt_size_min, new_pkt_size_var,
                   new_ipd, new_ipd_min, ipv4_total_len, ipv4_ttl,
                   ipv4_protocol, ipv4_tos, tcp_window, tcp_data_offset,
                   udp_len);

    } catch (const std::exception &e) {
      // The flow does not exist

      uint16_t ipv4_total_len = ntohs(ip_hdr->ip_len);
      uint8_t ipv4_ttl = ip_hdr->ip_ttl;
      uint8_t ipv4_protocol = ip_hdr->ip_p;
      uint8_t ipv4_tos = ip_hdr->ip_tos;

      uint32_t new_total_pkts = 1;
      uint32_t new_pkt_size_avg = ipv4_total_len;
      uint32_t new_pkt_size_max = ipv4_total_len;
      uint32_t new_pkt_size_min = ipv4_total_len;
      uint32_t new_pkt_ts = pkt_hdr->ts.tv_sec * 1000000 + pkt_hdr->ts.tv_usec;
      uint32_t new_ipd = 0;
      uint32_t new_ipd_min = 4294967295;
      uint32_t new_pkt_size_var = ipv4_total_len * ipv4_total_len;

      map_total_pkts[flow_feat] = new_total_pkts;
      map_pkt_size_avg[flow_feat] = new_pkt_size_avg;
      map_pkt_size_max[flow_feat] = new_pkt_size_max;
      map_pkt_size_min[flow_feat] = new_pkt_size_min;
      map_pkt_ts[flow_feat] = new_pkt_ts;
      map_ipd_min[flow_feat] = new_ipd_min;
      map_pkt_size_var[flow_feat] = new_pkt_size_var;

      uint16_t tcp_window = 0;
      uint8_t tcp_data_offset = 0;
      uint16_t udp_len = 0;

      if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp_hdr = reinterpret_cast<const struct tcphdr *>(
            pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
        tcp_window = ntohs(tcp_hdr->th_win);
        tcp_data_offset = tcp_hdr->th_off;
      } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp_hdr = reinterpret_cast<const struct udphdr *>(
            pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
        udp_len = ntohs(udp_hdr->uh_ulen);
      }

      // Write csv row
      std::fprintf(csv, "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
                   ip_hdr->ip_src.s_addr,ip_hdr->ip_dst.s_addr, new_total_pkts, new_pkt_size_avg,
                   new_pkt_size_max, new_pkt_size_min, new_pkt_size_var,
                   new_ipd, new_ipd_min, ipv4_total_len, ipv4_ttl,
                   ipv4_protocol, ipv4_tos, tcp_window, tcp_data_offset,
                   udp_len);
    }
  }

  std::printf("Finished processing %s\n", argv[1]);

  pcap_close(cap);
  std::fclose(csv_train);
  std::fclose(csv_test);

  return 0;
}