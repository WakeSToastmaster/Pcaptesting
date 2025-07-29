// WinPcapTesting.cpp: определяет точку входа для приложения.
//

#include "WinPcapTesting.h"
#include <fmt/format.h>
#include <Eigen/Dense>
#include "net.hpp"
#include "vector"
#include <cstdint>
#include <span>
#include "approx.h"

using namespace agm::net;

// char path[] = "C:\\job!_!\\Projects\\VS\\temp\\WinPcapTesting\\test-lidar.pcap";
//std::ofstream csv_data_file("C:\\Users\\KuznetsovEA\\Desktop\\temp\\data.csv");
// 
// 
//struct payload {
//    uint8_t* data = nullptr;  
//    int size = 0;             
//};

constexpr int measurements_amount = 40;
constexpr size_t NWFORMS_PKT = 20u;

struct A3Wform
{
    uint8_t is_emited;
    uint8_t sec[3u];
    uint8_t usec[3u];
    uint8_t ns;

    uint8_t meas[NWFORMS_PKT];
};

struct extrenum {
    uint8_t values[5];
};


bool process_measurements(const A3Wform& measurement, std::vector<extrenum>& extrenums){
    if (measurement.is_emited != '\0') return false;
    for (size_t i = 2; i < 18; i++)
    {
        if ((measurement.meas[i] > 40) && (measurement.meas[i] < 255) && (measurement.meas[i - 2] < measurement.meas[i - 1]) && (measurement.meas[i - 1] < measurement.meas[i]) && (measurement.meas[i] > measurement.meas[i + 1]) && (measurement.meas[i + 1] > measurement.meas[i + 2])) {
            extrenum newextrenum;
            for (size_t j = i-2; j < 5 + i - 2; j++)
            {
                newextrenum.values[j - i + 2] = measurement.meas[j];
            }
            extrenums.push_back(newextrenum);
            return true;
        }
    }
    return false;
}


void save_to_csv(std::span<const A3Wform>& data) {
    std::string path;
    std::cout << "Enter path of folder to save a file";
    std::cin >> path;
    path += "\\data.csv";
    std::ofstream csv_data_file(path);
    if (!csv_data_file.is_open()) {
        std::cerr << "Failed to open data.csv\n";
        return;
    }
    for (const auto& wform : data)
    {
        if (wform.is_emited == 0)
        {
            csv_data_file << "Emited\n";
        }
        else {
            csv_data_file << "Accepted\n";
        }
        if (wform.ns < 1000)
        {
            csv_data_file << static_cast<long>((wform.sec[0] * 256 + wform.sec[1]) * 256 + wform.sec[2] )<< "." << std::setw(6) << std::setfill('0') << static_cast<long>((wform.usec[0] * 256 + wform.usec[1]) * 256 + wform.usec[2]) << std::setw(3) << std::setfill('0') << static_cast<int>(wform.ns);
        }
        else
        {
            if (((static_cast<long>(wform.usec[0] * 256 + wform.usec[1]) * 256 + wform.usec[2])) < 999999) csv_data_file << static_cast<long>((wform.sec[0] * 256 + wform.sec[1]) * 256 + wform.sec[2]) << "." << std::setw(6) << std::setfill('0') << static_cast<long>((wform.usec[0] * 256 + wform.usec[1]) * 256 + wform.usec[2] + 1) << std::setw(3) << std::setfill('0') << static_cast<int>(wform.ns-1000);
            else csv_data_file << static_cast<long>((wform.sec[0] * 256 + wform.sec[1]) * 256 + wform.sec[2] +1)<< "." << std::setw(6) << std::setfill('0') << static_cast<long>((wform.usec[0] * 256 + wform.usec[1]) * 256 + wform.usec[2] -1000000)<< std::setw(3) << std::setfill('0') << static_cast<int>(wform.ns-1000);
        }
        csv_data_file << ",seconds,";
        for (uint8_t m : wform.meas)
            csv_data_file << static_cast<int>(m) << ",";
        csv_data_file << std::endl;
    }
    csv_data_file.close();
    std::cout << "saved!\n";
}
void save_to_csv(std::vector<extrenum> data) {
    std::string path;
    std::cout << "Enter path of folder to save a file";
    std::cin >> path;
    path += "\\data.csv";
    std::ofstream csv_data_file(path);
    if (!csv_data_file.is_open()) {
        std::cerr << "Failed to open data.csv\n";
        return;
    }
    for (size_t i = 0; i < 5; i++)
    {
        for (int j = 0; j < min(data.size(), 18000); j++) {
            csv_data_file << "," << static_cast<int>(data[j].values[i]);
        }
        csv_data_file << std::endl;
    }
    csv_data_file.close();
    std::cout << "saved!\n";
}


int strSize(const char* a) {
    int size = 0;
    while (a[size] != '\0') {
        ++size;
    }
    return size;
}

constexpr auto UDP_PROTO = 17;



bool get_pcap_pkt_data(pcap_t* pcap_file, std::span<const A3Wform>& data) {
    int data_begin_point = 0;
    const char* link_layer_type = pcap_datalink_val_to_description(pcap_datalink(pcap_file));

    if (memcmp(link_layer_type, "Ethernet", min(strSize(link_layer_type), strSize("Ethernet"))) == 0) {
        data_begin_point += 14;
    }
    else {
        std::cout << "ethernet link layer type expected but " << link_layer_type << " got.\n";
        return false;
    }

    pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    pcap_next_ex(pcap_file, &pkt_header, &pkt_data);

    u_int version_1st_byte = pkt_data[data_begin_point - 2];
    u_int version_2nd_byte = pkt_data[data_begin_point - 1];

    if ((version_1st_byte == 8) && (version_2nd_byte == 0)) {
        std::cout << "Pakage type is ipv4. Proceeding...\n";
        data_begin_point += 20;
    }
    else {
        std::cout << "Unexpected type =(\n";
        return false;
    }

    u_int protocol = pkt_data[data_begin_point + 9 - 20];
    if (protocol == UDP_PROTO) {
        std::cout << "Protocol is UDP, great!\n";
        data_begin_point += 8;
    }
    else {
        std::cout << "Unexpected protocol =(\n";
        return false;
    }

    int payload_size = pkt_header->len - data_begin_point;
    std::cout << "UDP payload collected. Total length is " << payload_size << " bytes.\n";

    auto wforms_ptr = reinterpret_cast<const A3Wform*>(pkt_data+data_begin_point);
    data = std::span{ wforms_ptr , measurements_amount};

    return true;
}




int main(int argc, char* argv[])
{
    char errbuff[PCAP_ERRBUF_SIZE] = { '\0' };
    FILE* file;
    auto err = fopen_s(&file, argv[1], "r");
    
    if (file == nullptr) {
        std::cout << "file reading error =(\n" << err;
        return 0;
    }
    std::cout << "file reading launched succesfully!\n";
    pcap_t *pcap_file = pcap_fopen_offline(file, errbuff)/*pcap_hopen_offline(_get_osfhandle(_fileno(file)), errbuff)*/;
    if (nullptr == pcap_file)
    {
        std::cout << fmt::format("pcap_open_offline error \n({})", errbuff);
        return 0;
    }
    std::cin >> errbuff;
    std::span<const A3Wform> data;
    std::vector<extrenum> extrenums(0);
    for (size_t i = 1; i < 2000; i++)
    {
        get_pcap_pkt_data(pcap_file, data);
        for (const auto& wform : data)
        {
            process_measurements(wform, extrenums);
        }
    }
    std::cout << extrenums.size() << std::endl;
    save_to_csv(extrenums);
    std::vector<std::vector<double>> y_data;
    for (const auto& ex : extrenums) {
        std::vector<double> y_values;
        for (int i = 0; i < 5; ++i) {
            y_values.push_back(static_cast<double>(ex.values[i]));
        }
        y_data.push_back(y_values);
    }

    Eigen::VectorXd total_coeffs = Eigen::VectorXd::Zero(3);
    int count = 0;

    for (const auto& y_values : y_data) {
        Eigen::VectorXd coeffs = approx::solve_system(y_values);
        total_coeffs += coeffs;
        count++;
    }

    Eigen::VectorXd avg_coeffs = total_coeffs / count;

    std::cout << "\n=== Final averaged coefficients ===\n";
    approx::print_coefficients(avg_coeffs);

    double mse = approx::calculate_mse(y_data, avg_coeffs);
    double mpe = approx::calculate_mean_percentage_error(y_data, avg_coeffs);

    std::cout << "\nQuality metrics:";
    std::cout << "\nMean Squared Error: " << mse;
    std::cout << "\nRoot Mean Squared Error: " << std::sqrt(mse);
    std::cout << "\nMean Percentage Error: " << mpe << "%";
    std::cout << "\nQuality metrics:";
    std::cout << "\nMean Squared Error: " << mse;
    std::cout << "\nRoot Mean Squared Error: " << std::sqrt(mse);
    std::cout << "\nMean Percentage Error: " << mpe << "%";
    char end_of_programm[100];
    std::cout << "enter any symbol to end.";
    std::cin >> end_of_programm;
    pcap_close(pcap_file);
    return 0;
}