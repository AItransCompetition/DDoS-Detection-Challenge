#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>
#include <assert.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <iostream>

using namespace std;


#define debug(x) std::cerr << #x << " = " << x
#define sp << " "
#define ln << "\n"

struct feat_adaptor {
	uint64_t _min, _max, _count, _last, _x_sum, _x2_sum;
	feat_adaptor() { _min = UINT32_MAX, _max  = _count = _x_sum = _x2_sum = _last = 0; }
	inline void append(uint64_t x) { _min = std::min(_min, x), _max = std::max(_max, x), _count += 1, _x_sum += x, _x2_sum += x * x, _last = x; }
	inline uint64_t min()const { return _min; }
	inline uint64_t max()const { return _max; }
	inline uint64_t sum()const { return _x_sum; }
	inline uint64_t avg()const { return _count > 0 ? _x_sum / _count : 0ull; }
	inline uint64_t std()const { return _count > 0 ? _x2_sum / _count - avg() * avg() : 0ull; }
	inline uint64_t count()const { return _count; }
	inline uint64_t last()const { return _last; }
};

// convert ipv4 from string to uint32_t
inline uint32_t ip2long(const char *ip) {
	uint32_t result = 0, cur = 0, cnt = 0;
	for (size_t i = 0, n = strlen(ip); i < n; i += 1) {
		if (ip[i] == '.') result = (result << 8) + cur, cur = 0, cnt += 1;
		else cur = cur * 10u + (uint32_t)(ip[i] - '0');
		assert(cur <= 255), assert(cnt <= 3);
	}
	return assert(cnt == 3), (result << 8) + cur;
}

inline void ip2string(uint32_t ip, char *result) {
	sprintf(result, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}
inline std::string ip2string(uint32_t ip) {
	using std::__cxx11::to_string;
	return to_string(ip >> 24) + "." + to_string((ip >> 16) & 255) + "." + to_string((ip >> 8) & 255) + "." + to_string(ip & 255);
}

std::vector<feat_adaptor*> pktlen, pktipd, pktts;
std::unordered_map<std::string, uint32_t> flow_index;
std::unordered_set<std::string> benigns;

int main(int argc, char **argv) {
	assert(argc >= 3);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *cap = pcap_open_offline(argv[1], errbuf);
	if (cap == nullptr) fprintf(stderr, "error reading pcap file: %s\n", errbuf), exit(1);
	FILE *csv = std::fopen(argv[2], "w");
	if (csv == nullptr) fprintf(stderr, "error opening csv file: %s\n", argv[2]), exit(1);

	FILE *benign = nullptr; bool has_label = (argc >= 4);
	std::printf("processing (pcap file: %s, label file: %s) -> (csv file: %s)...\n", argv[1], has_label ? argv[3] : "none", argv[2]);

	if (has_label) {
		int flow_cnt;
		benign = fopen(argv[3], "r");
		assert(fscanf(benign, "%d", &flow_cnt) != EOF);
		char flow_id[100];
		while (std::fscanf(benign, "%s", flow_id) != EOF)
			benigns.insert(std::string(flow_id));
	}

	const char csv_header[] =	"Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,"
								"Total Fwd Packets,Packet Length,Total Length of Fwd Packets,Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
								"Timestamp,IPD,Fwd IPD Max,Fwd IPD Min,Fwd IPD Mean,Fwd IPD Std,"
								"IP TTL,IP Diffserv,TCP Window,TCP Data Offset,Udp Len,Label\n";
	std::fprintf(csv, csv_header);

	struct pcap_pkthdr *pkt_hdr = new struct pcap_pkthdr;
	while (true) {
		static int iter = 0; iter += 1;
		const u_char *pkt_data = pcap_next(cap, pkt_hdr);
		if (pkt_data == nullptr) break;

		const struct ether_header *eth_hdr = reinterpret_cast<const struct ether_header *>(pkt_data);
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

		const struct ip *ip_hdr = reinterpret_cast<const struct ip *>(pkt_data + sizeof(*eth_hdr));
		if (ip_hdr->ip_p != IPPROTO_TCP && ip_hdr->ip_p != IPPROTO_UDP) continue;

		uint32_t src_ip = ntohl(ip_hdr->ip_src.s_addr), dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
		uint16_t tcp_window = 0, udp_len = 0, src_port = 0, dst_port= 0;
		uint8_t tcp_data_offset = 0, protocol = ip_hdr->ip_p;

		if (protocol == IPPROTO_TCP) {
			const struct tcphdr *tcp_hdr = reinterpret_cast<const struct tcphdr *>(pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
			tcp_window = ntohs(tcp_hdr->th_win), tcp_data_offset = tcp_hdr->th_off;
			src_port = tcp_hdr->th_sport, dst_port = tcp_hdr->th_dport;
		} else if (protocol == IPPROTO_UDP) {
			const struct udphdr *udp_hdr = reinterpret_cast<const struct udphdr *>(pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
			udp_len = ntohs(udp_hdr->uh_ulen);
			src_port = udp_hdr->uh_sport, dst_port = udp_hdr->uh_dport;
		}

		std::string quintuple = ip2string(src_ip) + "-" + ip2string(dst_ip) + "-" + std::__cxx11::to_string(src_port) + "-" + std::__cxx11::to_string(dst_port) + "-" + std::__cxx11::to_string(protocol);
		std::string flow_id = quintuple;

		if (!flow_index.count(flow_id)) {
			pktlen.push_back(new feat_adaptor);
			pktipd.push_back(new feat_adaptor);
			pktts.push_back(new feat_adaptor);
			flow_index[flow_id] = uint32_t(pktlen.size() - 1u);
		}
		uint32_t _flow_index = flow_index[flow_id];
		feat_adaptor &len = *pktlen[_flow_index], &ipd = *pktipd[_flow_index], &ts = *pktts[_flow_index];

		len.append(ntohs(ip_hdr->ip_len));
		uint32_t new_ts = uint32_t(pkt_hdr->ts.tv_sec * 1000000 + pkt_hdr->ts.tv_usec);
		if (ts.count()) ipd.append(new_ts - ts.last());
		ts.append(new_ts);

		std::fprintf(csv, "%s,%s,%u,%s,%u,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%u,%u,%u,%u,%u,",
						flow_id.c_str(), ip2string(src_ip).c_str(), (uint32_t)src_port, ip2string(dst_ip).c_str(), (uint32_t)dst_port, (uint32_t)protocol,
						len.count(), len.last(), len.sum(), len.max(), len.min(), len.avg(), len.std(), 
						ts.last(), ipd.last(), ipd.max(), ipd.min(), ipd.avg(), ipd.std(), 
						(uint32_t)ip_hdr->ip_ttl, (uint32_t)ip_hdr->ip_tos, (uint32_t)tcp_window, (uint32_t)tcp_data_offset, (uint32_t)udp_len);
		if (has_label) std::fprintf(csv, "%s\n", benigns.count(flow_id) ? "BENIGN" : "ATTACK");
		else std::fprintf(csv, "UNKNOWN\n");
	}

	std::printf("Finished processing %s\n", argv[1]);
	pcap_close(cap), std::fclose(csv);
	return 0;
}
